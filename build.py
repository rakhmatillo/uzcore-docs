#!/usr/bin/env python3
"""
nSOC / UzCORE telemetry documentation builder.

    python build.py                      -> dist/  (working copy; marked DRAFT if it differs from the last release)
    python build.py release 1.1.0 "note" -> snapshot schemas/ + docs/ into releases/1.1.0/, then build
    python build.py check                -> validate schemas + i18n, print unreleased diff, exit 1 if invalid

Sources of truth
    schemas/*.schema.json   field definitions (JSON Schema 2020-12). Field tables are GENERATED from these.
    docs/guide.<lang>.md    prose guide. guide.uz.md is canonical; en/ru fall back to uz when missing.
    i18n/ui.json            UI strings per language.
    i18n/schema.<lang>.json translated field descriptions, keyed "<schema-id>#<json-pointer>".
    releases/<version>/     immutable snapshots. The changelog is computed by diffing consecutive snapshots.
"""
import json, re, sys, shutil, hashlib, html, datetime, copy
from pathlib import Path

try:
    import markdown
except ImportError:
    sys.exit("pip install markdown")

ROOT = Path(__file__).resolve().parent
SCHEMAS = ROOT / "schemas"
DOCS = ROOT / "docs"
I18N = ROOT / "i18n"
RELEASES = ROOT / "releases"
DIST = ROOT / "dist"
LANGS = ["uz", "en", "ru"]
DEFAULT_LANG = "uz"

SCHEMA_ORDER = ["incident-report", "alert", "asset-inventory"]


# ----------------------------------------------------------------------------- loading
def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def schema_id_from_file(p: Path) -> str:
    return p.name.replace(".schema.json", "")


def load_sources(base: Path):
    """Load schemas + docs + i18n from a base dir (ROOT or a release snapshot)."""
    schemas = {}
    for p in sorted((base / "schemas").glob("*.schema.json")):
        schemas[schema_id_from_file(p)] = {"id": schema_id_from_file(p), "file": p.name, "schema": load_json(p),
                                            "raw": p.read_text(encoding="utf-8")}
    ordered = {k: schemas[k] for k in SCHEMA_ORDER if k in schemas}
    ordered.update({k: v for k, v in schemas.items() if k not in ordered})
    guides = {}
    for lang in LANGS:
        p = base / "docs" / f"guide.{lang}.md"
        if p.exists():
            guides[lang] = p.read_text(encoding="utf-8")
    i18n = {}
    for lang in LANGS:
        p = base / "i18n" / f"schema.{lang}.json"
        i18n[lang] = load_json(p) if p.exists() else {}
    return {"schemas": ordered, "guides": guides, "i18n": i18n}


# ----------------------------------------------------------------------------- schema flattening
def type_label(node: dict) -> str:
    if "const" in node:
        return f"const {json.dumps(node['const'], ensure_ascii=False)}"
    if "oneOf" in node:
        parts = [type_label(n) for n in node["oneOf"]]
        return " | ".join(parts)
    t = node.get("type")
    if t == "array":
        items = node.get("items", {})
        inner = type_label(items) if items else "any"
        if items.get("type") == "object":
            inner = "object"
        return f"array<{inner}>"
    if t == "string" and node.get("format"):
        return f"string ({node['format']})"
    if t == "string" and "enum" in node:
        return "enum"
    if t == "integer" and "enum" in node:
        return "enum (integer)"
    if t is None and "enum" in node:
        return "enum"
    return t or "any"


def constraints_of(node: dict) -> list:
    out = []
    for k in ("minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems", "minProperties"):
        if k in node:
            out.append(f"{k}={node[k]}")
    if node.get("uniqueItems"):
        out.append("uniqueItems")
    if "pattern" in node:
        out.append(("pattern", node["pattern"]))
    if node.get("additionalProperties") is False and node.get("type") == "object":
        out.append("no extra props")
    return out


def enum_of(node: dict):
    if "enum" in node:
        return node["enum"]
    if node.get("type") == "array" and "enum" in node.get("items", {}):
        return node["items"]["enum"]
    return None


def collect_conditional_required(obj: dict) -> set:
    """Names made required by any if/then inside this object's allOf."""
    req = set()
    for rule in obj.get("allOf", []):
        then = rule.get("then", {})
        for r in then.get("required", []):
            req.add(r)
    return req


def flatten(schema: dict, sid: str):
    """Return ordered list of field rows for a schema."""
    rows = []

    def walk(node: dict, pointer: str, display: str, depth: int, required_names: set, cond_names: set, in_array: bool):
        props = node.get("properties", {})
        for name, sub in props.items():
            ptr = f"{pointer}/properties/{name}"
            disp = f"{display}.{name}" if display else name
            if name in required_names:
                req = "R*" if in_array else "R"
            elif name in cond_names:
                req = "C"
            else:
                req = "O"
            effective = sub
            # unwrap oneOf [X, null]
            nullable = False
            if "oneOf" in sub and any(n.get("type") == "null" for n in sub["oneOf"]):
                nullable = True
                effective = next((n for n in sub["oneOf"] if n.get("type") != "null"), sub)
            row = {
                "schema": sid, "pointer": ptr, "path": disp, "name": name, "depth": depth,
                "type": type_label(sub) + (" | null" if nullable and "oneOf" not in sub else ""),
                "req": req, "constraints": constraints_of(effective), "enum": enum_of(effective),
                "description": sub.get("description", ""),
                "is_object": effective.get("type") == "object" or ("properties" in effective),
                "is_array_of_objects": effective.get("type") == "array" and effective.get("items", {}).get("type") == "object",
            }
            rows.append(row)
            if row["is_object"]:
                walk(effective, ptr, disp, depth + 1, set(effective.get("required", [])),
                     collect_conditional_required(effective), in_array)
            elif row["is_array_of_objects"]:
                items = effective["items"]
                walk(items, f"{ptr}/items", disp + "[]", depth + 1, set(items.get("required", [])),
                     collect_conditional_required(items), True)

    walk(schema, "#", "", 0, set(schema.get("required", [])), collect_conditional_required(schema), False)
    return rows


def describe_condition(if_node: dict) -> str:
    props = if_node.get("properties", {})
    parts = []
    for k, v in props.items():
        if "const" in v:
            parts.append(f"`{k}` = `{json.dumps(v['const'], ensure_ascii=False)}`")
        elif "enum" in v:
            parts.append(f"`{k}` ∈ {{{', '.join('`'+json.dumps(e, ensure_ascii=False)+'`' for e in v['enum'])}}}")
        elif "contains" in v:
            c = v["contains"]
            val = c.get("const", c.get("enum"))
            parts.append(f"`{k}` contains `{json.dumps(val, ensure_ascii=False)}`")
        else:
            parts.append(f"`{k}` …")
    if not props and if_node.get("required"):
        parts.append(" & ".join(f"`{r}` present" for r in if_node["required"]))
    if "not" in if_node:
        return "NOT (" + describe_condition(if_node["not"]) + ")"
    return " & ".join(parts) or "…"


def describe_then(then: dict) -> list:
    out = []
    if then.get("required"):
        out.append("required: " + ", ".join(f"`{r}`" for r in then["required"]))
    if "not" in then:
        n = then["not"]
        if "anyOf" in n:
            names = [r for a in n["anyOf"] for r in a.get("required", [])]
            out.append("forbidden: " + ", ".join(f"`{r}`" for r in names))
        elif n.get("required"):
            out.append("forbidden: " + ", ".join(f"`{r}`" for r in n["required"]))
        elif n.get("properties"):
            for k, v in n["properties"].items():
                out.append(f"`{k}` must not be `{json.dumps(v.get('const'), ensure_ascii=False)}`")
    for k, v in then.get("properties", {}).items():
        if "enum" in v:
            out.append(f"`{k}` ∈ {{{', '.join('`'+str(e)+'`' for e in v['enum'])}}}")
        elif "const" in v:
            out.append(f"`{k}` = `{json.dumps(v['const'], ensure_ascii=False)}`")
        elif "maxItems" in v:
            out.append(f"`{k}` maxItems={v['maxItems']}")
        elif "contains" in v:
            c = v["contains"]
            out.append(f"`{k}` must contain `{json.dumps(c.get('const', c.get('enum')), ensure_ascii=False)}`")
        elif "not" in v and v["not"].get("required"):
            out.append(f"`{k}` must not contain " + ", ".join(f"`{r}`" for r in v["not"]["required"]))
        elif "properties" in v:
            for kk, vv in v["properties"].items():
                if "contains" in vv:
                    c = vv["contains"]
                    out.append(f"`{k}.{kk}` must contain `{json.dumps(c.get('const', c.get('enum')), ensure_ascii=False)}`")
                elif "const" in vv:
                    out.append(f"`{k}.{kk}` = `{json.dumps(vv['const'], ensure_ascii=False)}`")
        elif v.get("type"):
            out.append(f"`{k}` must be {v['type']}")
    return out or ["(see schema)"]


def collect_rules(schema: dict, sid: str):
    """All if/then rules anywhere in the schema, with the object path they apply to."""
    rules = []

    def walk(node, display):
        if not isinstance(node, dict):
            return
        for rule in node.get("allOf", []):
            if "if" in rule:
                rules.append({"scope": display or "(root)", "if": describe_condition(rule["if"]),
                              "then": describe_then(rule.get("then", {})), "raw": rule})
        for name, sub in node.get("properties", {}).items():
            disp = f"{display}.{name}" if display else name
            if isinstance(sub, dict):
                walk(sub, disp)
                if sub.get("type") == "array" and isinstance(sub.get("items"), dict):
                    walk(sub["items"], disp + "[]")
                for alt in sub.get("oneOf", []):
                    walk(alt, disp)

    walk(schema, "")
    return rules


# ----------------------------------------------------------------------------- diffing
KEYS = ("type", "req", "constraints", "enum", "description")


def row_index(rows):
    return {r["pointer"]: r for r in rows}


def diff_rows(old_rows, new_rows):
    o, n = row_index(old_rows), row_index(new_rows)
    added = [n[p] for p in n if p not in o]
    removed = [o[p] for p in o if p not in n]
    changed = []
    for p in n:
        if p in o:
            deltas = []
            for k in KEYS:
                if o[p][k] != n[p][k]:
                    deltas.append({"attr": k, "old": o[p][k], "new": n[p][k]})
            if deltas:
                changed.append({"row": n[p], "deltas": deltas})
    return {"added": added, "removed": removed, "changed": changed}


def guide_sections(md_text: str):
    """Split a markdown guide into (heading, body-hash) for h1/h2/h3, ignoring headings inside code fences."""
    heads = list(iter_headings(md_text))
    lines = md_text.splitlines()
    out = []
    for idx, (ln, level, title) in enumerate(heads):
        end = heads[idx + 1][0] if idx + 1 < len(heads) else len(lines)
        body = "\n".join(lines[ln + 1:end])
        out.append((title, hashlib.sha1(body.encode()).hexdigest()))
    return out


def diff_guides(old_md: str, new_md: str):
    o = dict(guide_sections(old_md or ""))
    n = dict(guide_sections(new_md or ""))
    return {"added": [h for h in n if h not in o], "removed": [h for h in o if h not in n],
            "changed": [h for h in n if h in o and o[h] != n[h]]}


def diff_sources(old, new):
    out = {"schemas": {}, "guide": {}}
    sids = list(dict.fromkeys(list(new["schemas"]) + list(old["schemas"])))
    for sid in sids:
        o = flatten(old["schemas"][sid]["schema"], sid) if sid in old["schemas"] else []
        n = flatten(new["schemas"][sid]["schema"], sid) if sid in new["schemas"] else []
        d = diff_rows(o, n)
        if sid not in old["schemas"]:
            d["new_schema"] = True
        if sid not in new["schemas"]:
            d["removed_schema"] = True
        if d["added"] or d["removed"] or d["changed"] or d.get("new_schema") or d.get("removed_schema"):
            out["schemas"][sid] = d
    for lang in LANGS:
        if lang in new["guides"] and lang not in old["guides"]:
            out["guide"][lang] = {"added": [], "removed": [], "changed": [], "new_guide": True}
        elif lang in old["guides"] and lang not in new["guides"]:
            out["guide"][lang] = {"added": [], "removed": [], "changed": [], "removed_guide": True}
        elif lang in new["guides"]:
            d = diff_guides(old["guides"][lang], new["guides"][lang])
            if d["added"] or d["removed"] or d["changed"]:
                out["guide"][lang] = d
    return out


def diff_is_empty(d):
    return not d["schemas"] and not d["guide"]


# ----------------------------------------------------------------------------- releases
def version_key(v: str):
    return tuple(int(x) if x.isdigit() else x for x in re.split(r"[.\-]", v))


def list_releases():
    rel = []
    if RELEASES.exists():
        for d in RELEASES.iterdir():
            if d.is_dir() and (d / "meta.json").exists():
                meta = load_json(d / "meta.json")
                rel.append({"version": d.name, "dir": d, "meta": meta})
    rel.sort(key=lambda r: version_key(r["version"]))
    return rel


def make_release(version: str, note: str):
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        sys.exit("version must be MAJOR.MINOR.PATCH, e.g. 1.1.0")
    dest = RELEASES / version
    if dest.exists():
        sys.exit(f"release {version} already exists")
    rels = list_releases()
    if rels and version_key(version) <= version_key(rels[-1]["version"]):
        sys.exit(f"version must be greater than last release {rels[-1]['version']}")
    for sub in ("schemas", "docs", "i18n"):
        shutil.copytree(ROOT / sub, dest / sub)
    meta = {"version": version, "date": datetime.date.today().isoformat(), "note": note}
    (dest / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"release {version} snapshotted -> {dest.relative_to(ROOT)}")


# ----------------------------------------------------------------------------- rendering helpers
def esc(s) -> str:
    return html.escape(str(s), quote=True)


def inline_md(s: str) -> str:
    """Tiny inline markdown: `code`, **bold**."""
    s = esc(s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
    return s


def slugify(s: str) -> str:
    s = re.sub(r"[`*]", "", s).strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"[\s_]+", "-", s)
    return s or "s"


def iter_headings(md_text: str):
    """Yield (line_no, level, title) for ATX headings outside fenced code blocks."""
    fence = None
    for i, line in enumerate(md_text.splitlines()):
        f = re.match(r"^\s*(```|~~~)", line)
        if f:
            fence = None if fence == f.group(1) else (fence or f.group(1))
            continue
        if fence:
            continue
        m = re.match(r"^(#{1,3})\s+(.*)", line)
        if m:
            yield i, len(m.group(1)), m.group(2).strip()


def render_guide(md_text: str, prefix: str):
    """Render markdown to HTML, returns (html, toc[list of (level, title, id)])."""
    lines = md_text.splitlines()
    toc, used = [], set()
    for i, level, title in iter_headings(md_text):
        sid = f"{prefix}-{slugify(title)}"
        n, base = 2, sid
        while sid in used:
            sid = f"{base}-{n}"; n += 1
        used.add(sid)
        toc.append((level, title, sid))
        lines[i] = f"{'#' * level} {title} {{#{sid}}}"
    md = markdown.Markdown(extensions=["tables", "fenced_code", "attr_list", "sane_lists"])
    return md.convert("\n".join(lines)), toc


class ML:
    """Multilingual text helper: ML(ui)('key') -> spans for every language."""

    def __init__(self, ui):
        self.ui = ui

    def t(self, lang, key):
        return self.ui.get(key, {}).get(lang) or self.ui.get(key, {}).get("en") or key

    def __call__(self, key, raw=False):
        return "".join(f'<span data-lang="{l}">{self.t(l, key) if raw else esc(self.t(l, key))}</span>' for l in LANGS)

    @staticmethod
    def spans(per_lang: dict):
        """per_lang: lang -> html. Languages sharing identical html are merged into one span."""
        groups = {}
        for l in LANGS:
            groups.setdefault(per_lang.get(l, per_lang.get(DEFAULT_LANG, "")), []).append(l)
        return "".join(f'<span data-lang="{" ".join(ls)}">{h}</span>' for h, ls in groups.items())


def desc_html(row, i18n, T: ML):
    """Description for every language with fallback markers."""
    key = f"{row['schema']}{row['pointer']}"
    per = {}
    for l in LANGS:
        tr = i18n.get(l, {}).get(key)
        if tr:
            per[l] = inline_md(tr)
        elif row["description"]:
            fb = "" if l == DEFAULT_LANG else f' <span class="fb" title="{esc(T.t(l, "fallback"))}">{DEFAULT_LANG.upper()}</span>'
            per[l] = inline_md(row["description"]) + fb
        else:
            per[l] = ""
    return ML.spans(per)


def i18n_text(i18n, key, default):
    return ML.spans({l: inline_md(i18n.get(l, {}).get(key) or default) for l in LANGS})


# ----------------------------------------------------------------------------- page
CSS = r"""
:root{
  --bg:#f7f8fa;--panel:#fff;--ink:#1c2230;--muted:#5c6675;--line:#e3e6ea;--accent:#0f5fd1;--accent-ink:#fff;
  --code-bg:#eef1f5;--r:#c62828;--c:#b26a00;--o:#4b5563;--add:#1b7f3b;--rm:#b42318;--chg:#9a5b00;
  --badge:#e8eefc;--draft:#fff4d6;--draft-ink:#7a4f00;--sans:system-ui,-apple-system,"Segoe UI",Roboto,Inter,sans-serif;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
  --bg:#0f1319;--panel:#161b23;--ink:#e6e9ee;--muted:#98a2b3;--line:#273041;--accent:#6aa5ff;--accent-ink:#0b1220;
  --code-bg:#1f2632;--r:#ff7b72;--c:#e3b341;--o:#9aa4b2;--add:#3fb950;--rm:#f85149;--chg:#d29922;--badge:#1e2a44;--draft:#3a2e08;--draft-ink:#ffd978;}}
:root[data-theme=dark]{
  --bg:#0f1319;--panel:#161b23;--ink:#e6e9ee;--muted:#98a2b3;--line:#273041;--accent:#6aa5ff;--accent-ink:#0b1220;
  --code-bg:#1f2632;--r:#ff7b72;--c:#e3b341;--o:#9aa4b2;--add:#3fb950;--rm:#f85149;--chg:#d29922;--badge:#1e2a44;--draft:#3a2e08;--draft-ink:#ffd978;}
*{box-sizing:border-box}
html{scroll-padding-top:70px}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 var(--sans)}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
code,pre{font-family:var(--mono);font-size:.88em}
code{background:var(--code-bg);padding:.1em .35em;border-radius:4px}
pre{background:var(--code-bg);padding:12px 14px;border-radius:8px;overflow:auto;line-height:1.45}
pre code{background:none;padding:0}
header.top{position:sticky;top:0;z-index:20;background:var(--panel);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:14px;padding:10px 16px;flex-wrap:wrap}
header .brand{font-weight:700;letter-spacing:.2px}
header .ver{background:var(--badge);color:var(--accent);font-family:var(--mono);font-size:.8rem;padding:3px 8px;border-radius:999px}
header .ver.draft{background:var(--draft);color:var(--draft-ink)}
header .spacer{flex:1}
header input[type=search]{border:1px solid var(--line);background:var(--bg);color:var(--ink);padding:7px 10px;border-radius:8px;min-width:220px}
.lang button,.theme button{border:1px solid var(--line);background:var(--bg);color:var(--ink);padding:5px 9px;border-radius:6px;cursor:pointer;font:inherit;font-size:.85rem}
.lang button.on{background:var(--accent);color:var(--accent-ink);border-color:var(--accent)}
.lang{display:flex;gap:4px}
button.burger{display:none;border:1px solid var(--line);background:var(--bg);color:var(--ink);border-radius:6px;padding:5px 9px;font:inherit}
.layout{display:grid;grid-template-columns:290px minmax(0,1fr);gap:0;max-width:1500px;margin:0 auto}
nav.side{position:sticky;top:58px;height:calc(100vh - 58px);overflow:auto;padding:16px 12px 40px 16px;border-right:1px solid var(--line);font-size:.9rem}
nav.side h4{margin:14px 0 6px;font-size:.72rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
nav.side a{display:block;padding:3px 8px;border-radius:6px;color:var(--ink)}
nav.side a:hover{background:var(--code-bg);text-decoration:none}
nav.side a.l2{padding-left:18px}nav.side a.l3{padding-left:32px;color:var(--muted);font-size:.85rem}
nav.side a.active{background:var(--badge);color:var(--accent)}
main{padding:24px 32px 120px;min-width:0}
main h1{font-size:1.9rem;margin:.2em 0 .4em}main h2{font-size:1.4rem;margin:2em 0 .6em;padding-top:.4em;border-top:1px solid var(--line)}
main h3{font-size:1.12rem;margin:1.6em 0 .5em}main h4{margin:1.2em 0 .4em}
main section.block{margin-bottom:36px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:14px 0}
.draft-banner{background:var(--draft);color:var(--draft-ink);border:1px solid #e6c56a44;border-radius:10px;padding:12px 16px;margin-bottom:18px}
table{border-collapse:collapse;width:100%;font-size:.9rem;margin:.6em 0 1.2em}
th,td{border-bottom:1px solid var(--line);padding:7px 9px;text-align:left;vertical-align:top}
th{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);background:var(--panel)}
.fields th{position:sticky;top:58px;z-index:1}
main .md table{display:block;overflow:auto}
.fields td.f{font-family:var(--mono);white-space:nowrap}
.fields .d0 td.f{font-weight:600}
.fields .ind{display:inline-block;width:14px;height:1px}
.fields td.ty{font-family:var(--mono);color:var(--muted);white-space:nowrap;font-size:.82rem}
.req{display:inline-block;font-weight:700;font-size:.75rem;padding:1px 6px;border-radius:4px;border:1px solid}
.req.R{color:var(--r);border-color:var(--r)}.req.C{color:var(--c);border-color:var(--c)}.req.O{color:var(--o);border-color:var(--o)}
.cons{color:var(--muted);font-size:.78rem;font-family:var(--mono)}
.enum{margin-top:4px}
.enum span{display:inline-block;background:var(--code-bg);border-radius:4px;padding:0 5px;margin:1px 3px 1px 0;font-family:var(--mono);font-size:.78rem}
.enum details summary{cursor:pointer;color:var(--accent);font-size:.8rem}
.since{display:inline-block;font-size:.68rem;color:var(--accent);background:var(--badge);border-radius:4px;padding:0 5px;margin-left:6px;vertical-align:middle}
.fb{display:inline-block;font-size:.66rem;color:var(--muted);border:1px dashed var(--line);border-radius:4px;padding:0 4px;margin-left:4px;vertical-align:middle;cursor:help}
.chg-add{color:var(--add)}.chg-rm{color:var(--rm)}.chg-chg{color:var(--chg)}
.changelog .entry{border-left:3px solid var(--line);padding:4px 0 4px 16px;margin:14px 0}
.changelog .entry.latest{border-color:var(--accent)}
.changelog .v{font-family:var(--mono);font-weight:700;font-size:1.05rem}
.changelog .date{color:var(--muted);font-size:.85rem;margin-left:8px}
#versions td:nth-child(2){white-space:nowrap}
.changelog ul{margin:.3em 0 .3em 1.2em;padding:0}
.changelog li{margin:2px 0}
.delta{font-family:var(--mono);font-size:.8rem}
.delta .old{text-decoration:line-through;color:var(--rm)}.delta .new{color:var(--add)}
.rules li{margin:4px 0}
.meta{color:var(--muted);font-size:.88rem}
.dl a{margin-right:14px}
.hidden{display:none!important}
.hit{background:#ffe58a66}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;font-size:.9rem}
.kv dt{color:var(--muted)}.kv dd{margin:0}
footer{color:var(--muted);font-size:.8rem;border-top:1px solid var(--line);padding:16px 32px;text-align:center}
@media (max-width:900px){
  .layout{grid-template-columns:1fr}
  nav.side{position:fixed;left:0;top:58px;width:290px;background:var(--panel);transform:translateX(-100%);transition:transform .2s;z-index:15}
  nav.side.open{transform:none}
  button.burger{display:inline-block}
  main{padding:16px 16px 100px}
  footer{padding:16px}
  th{position:static}
}
"""

JS = r"""
(function(){
  const LANGS=%(langs)s, DEFAULT=%(default)s;
  const root=document.documentElement;
  function setLang(l){
    if(!LANGS.includes(l)) l=DEFAULT;
    root.setAttribute('lang',l);
    document.querySelectorAll('[data-lang]').forEach(el=>{el.classList.toggle('hidden',!el.dataset.lang.split(' ').includes(l));});
    document.querySelectorAll('.lang button').forEach(b=>b.classList.toggle('on',b.dataset.set===l));
    try{localStorage.setItem('nsoc-lang',l);}catch(e){}
    const u=new URL(location);u.searchParams.set('lang',l);history.replaceState(null,'',u);
    const q=document.getElementById('q');try{q.placeholder=JSON.parse(q.dataset.ph)[l];document.getElementById('qstatus').dataset.label=JSON.parse(document.getElementById('qstatus').dataset.labels)[l];}catch(e){}
  }
  let initial=DEFAULT;
  try{initial=new URL(location).searchParams.get('lang')||localStorage.getItem('nsoc-lang')||DEFAULT;}catch(e){}
  setLang(initial);
  document.querySelectorAll('.lang button').forEach(b=>b.addEventListener('click',()=>setLang(b.dataset.set)));
  // theme
  function setTheme(t){ if(t) root.setAttribute('data-theme',t); else root.removeAttribute('data-theme'); try{t?localStorage.setItem('nsoc-theme',t):localStorage.removeItem('nsoc-theme');}catch(e){} }
  try{ const t=localStorage.getItem('nsoc-theme'); if(t) setTheme(t);}catch(e){}
  const tb=document.querySelector('.theme button');
  tb&&tb.addEventListener('click',()=>{const cur=root.getAttribute('data-theme');const dark=cur?cur==='dark':matchMedia('(prefers-color-scheme:dark)').matches;setTheme(dark?'light':'dark');});
  // sidebar
  const nav=document.querySelector('nav.side');
  const burger=document.querySelector('button.burger');
  burger&&burger.addEventListener('click',()=>nav.classList.toggle('open'));
  nav.addEventListener('click',e=>{if(e.target.tagName==='A'&&innerWidth<=900)nav.classList.remove('open');});
  // scroll spy
  const links=[...nav.querySelectorAll('a[href^="#"]')];
  const targets=links.map(a=>document.getElementById(a.getAttribute('href').slice(1))).filter(Boolean);
  let ticking=false;
  function spy(){
    ticking=false; let best=null;
    for(const t of targets){ if(t.getBoundingClientRect().top-80<=0) best=t; else break; }
    links.forEach(a=>a.classList.toggle('active',best&&a.getAttribute('href')==='#'+best.id));
    if(best){const a=links.find(a=>a.getAttribute('href')==='#'+best.id); if(a&&a.scrollIntoView&&innerWidth>900){const r=a.getBoundingClientRect(),n=nav.getBoundingClientRect(); if(r.top<n.top||r.bottom>n.bottom) a.scrollIntoView({block:'nearest'});}}
  }
  addEventListener('scroll',()=>{if(!ticking){requestAnimationFrame(spy);ticking=true;}});spy();
  // search: filters schema field rows and guide headings
  const q=document.getElementById('q');
  const rows=[...document.querySelectorAll('table.fields tbody tr')];
  const status=document.getElementById('qstatus');
  function search(){
    const v=q.value.trim().toLowerCase();
    let n=0;
    rows.forEach(r=>{const hit=!v||r.dataset.search.includes(v);r.classList.toggle('hidden',!hit);if(hit&&v)n++;});
    document.querySelectorAll('.fields-wrap').forEach(w=>{const any=[...w.querySelectorAll('tbody tr')].some(r=>!r.classList.contains('hidden'));w.querySelector('.noresults').classList.toggle('hidden',any);});
    status.textContent=v?(n+' '+status.dataset.label):'';
  }
  q.addEventListener('input',search);
  addEventListener('keydown',e=>{if(e.key==='/'&&document.activeElement!==q){e.preventDefault();q.focus();}});
  // open <details> containing hash target
  function openTarget(){const h=location.hash&&document.getElementById(location.hash.slice(1)); if(h){let d=h.closest('details'); while(d){d.open=true; d=d.parentElement&&d.parentElement.closest('details');}}}
  addEventListener('hashchange',openTarget); openTarget();
  if(location.hash){const el=document.getElementById(decodeURIComponent(location.hash.slice(1))); if(el) requestAnimationFrame(()=>el.scrollIntoView());}
})();
"""


def render_fields_table(rows, i18n, T: ML, since, sid):
    out = [f'<div class="fields-wrap"><table class="fields"><thead><tr>'
           f'<th>{T("col.field")}</th><th>{T("col.type")}</th><th>{T("col.req")}</th><th>{T("col.desc")}</th></tr></thead><tbody>']
    for r in rows:
        ind = '<span class="ind"></span>' * r["depth"]
        reqcls = r["req"][0]
        cons = " · ".join((f'<abbr title="{esc(c[1])}">pattern</abbr>' if isinstance(c, tuple) else esc(c)) for c in r["constraints"])
        enum_html = ""
        if r["enum"]:
            chips = "".join(f"<span>{esc(e)}</span>" for e in r["enum"])
            if len(r["enum"]) > 12:
                enum_html = f'<div class="enum"><details><summary>{len(r["enum"])} {T("enum.values")}</summary>{chips}</details></div>'
            else:
                enum_html = f'<div class="enum">{chips}</div>'
        sv = since.get(f"{sid}#{r['pointer']}")
        since_html = f'<span class="since">{esc(sv)}</span>' if sv else ""
        anchor = f"{sid}--{r['path'].replace('[]', '').replace('.', '-')}"
        blob = (r["path"] + " " + r["description"] + " " + " ".join(map(str, r["enum"] or []))).lower()
        out.append(
            f'<tr id="{esc(anchor)}" class="d{min(r["depth"], 3)}" data-search="{esc(blob)}">'
            f'<td class="f">{ind}<a href="#{esc(anchor)}">{esc(r["name"])}</a>{since_html}</td>'
            f'<td class="ty">{esc(r["type"])}{("<br><span class=cons>" + cons + "</span>") if cons else ""}</td>'
            f'<td><span class="req {reqcls}">{esc(r["req"])}</span></td>'
            f'<td>{desc_html(r, i18n, T)}{enum_html}</td></tr>')
    out.append(f'</tbody></table><p class="noresults hidden meta">{T("search.none")}</p></div>')
    return "".join(out)


def render_schema_section(entry, rows, rules, i18n, T: ML, since, current_version):
    sid = entry["id"]
    s = entry["schema"]
    n_req = sum(1 for r in rows if r["req"].startswith("R"))
    props = s.get("properties", {})
    parts = [f'<section class="block" id="schema-{sid}">',
             f'<h2>{i18n_text(i18n, f"{sid}#title", s.get("title", sid))}</h2>',
             f'<p>{i18n_text(i18n, f"{sid}#description", s.get("description", ""))}</p>',
             '<div class="card"><dl class="kv">',
             f'<dt>{T("schema.file")}</dt><dd><code>{esc(entry["file"])}</code> — <a href="schemas/{esc(current_version)}/{esc(entry["file"])}" download>{T("download")}</a></dd>',
             f'<dt>$id</dt><dd><code>{esc(s.get("$id", ""))}</code></dd>',
             f'<dt>telemetry_type</dt><dd><code>{esc(props.get("telemetry_type", {}).get("const", ""))}</code></dd>',
             f'<dt>schema_version</dt><dd><code>{esc(props.get("schema_version", {}).get("const", ""))}</code></dd>',
             f'<dt>{T("schema.fields")}</dt><dd>{len(rows)} ({n_req} R)</dd>',
             '</dl></div>',
             f'<h3>{T("schema.fieldtable")}</h3><p class="meta">{T("legend")}</p>',
             render_fields_table(rows, i18n, T, since, sid)]
    if rules:
        parts.append(f'<h3>{T("schema.rules")}</h3><p class="meta">{T("schema.rules.hint")}</p><ul class="rules">')
        for r in rules:
            parts.append(f'<li><code>{esc(r["scope"])}</code>: <b>if</b> {inline_md(r["if"])} → <b>then</b> ' + "; ".join(inline_md(x) for x in r["then"]) + "</li>")
        parts.append("</ul>")
    parts.append("</section>")
    return "".join(parts)


def render_delta(delta):
    def fmt(v):
        if isinstance(v, list):
            return ", ".join(("=".join(x) if isinstance(x, tuple) else str(x)) for x in v) if v else "∅"
        return str(v) if v not in (None, "") else "∅"
    return (f'<span class="delta">{esc(delta["attr"])}: <span class="old">{esc(fmt(delta["old"]))}</span> → '
            f'<span class="new">{esc(fmt(delta["new"]))}</span></span>')


def render_changelog(entries, T: ML):
    """entries: list of {version,date,note,diff,is_draft} newest first."""
    out = ['<section class="block changelog" id="changelog">', f'<h2>{T("nav.changelog")}</h2>',
           f'<p class="meta">{T("changelog.hint")}</p>']
    for i, e in enumerate(entries):
        cls = "entry latest" if i == 0 else "entry"
        label = T("draft") if e["is_draft"] else "v" + esc(e["version"])
        out.append(f'<div class="{cls}" id="changelog-{esc(e["version"])}"><span class="v">{label}</span><span class="date">{esc(e["date"])}</span>')
        if e.get("note"):
            out.append(f'<p>{inline_md(e["note"])}</p>')
        d = e["diff"]
        if d is None:
            out.append(f'<p class="meta">{T("changelog.initial")}</p>')
        elif diff_is_empty(d):
            out.append(f'<p class="meta">{T("changelog.nochange")}</p>')
        else:
            for sid, sd in d["schemas"].items():
                out.append(f'<h4><code>{esc(sid)}</code></h4><ul>')
                if sd.get("new_schema"):
                    out.append(f'<li class="chg-add">{T("chg.newschema")}</li>')
                if sd.get("removed_schema"):
                    out.append(f'<li class="chg-rm">{T("chg.removedschema")}</li>')
                for r in sd["added"]:
                    anchor = f"{sid}--{r['path'].replace('[]', '').replace('.', '-')}"
                    out.append(f'<li><span class="chg-add">+</span> <a href="#{esc(anchor)}"><code>{esc(r["path"])}</code></a> <span class="req {r["req"][0]}">{esc(r["req"])}</span> <span class="meta">{esc(r["type"])}</span> — {T("chg.added")}</li>')
                for r in sd["removed"]:
                    out.append(f'<li><span class="chg-rm">−</span> <code>{esc(r["path"])}</code> — {T("chg.removed")}</li>')
                for c in sd["changed"]:
                    anchor = f"{sid}--{c['row']['path'].replace('[]', '').replace('.', '-')}"
                    out.append(f'<li><span class="chg-chg">~</span> <a href="#{esc(anchor)}"><code>{esc(c["row"]["path"])}</code></a>: ' + "; ".join(render_delta(x) for x in c["deltas"]) + "</li>")
                out.append("</ul>")
            for glang, gd in d["guide"].items():
                out.append(f'<h4>{T("chg.guide")} ({glang.upper()})</h4><ul>')
                if gd.get("new_guide"):
                    out.append(f'<li class="chg-add">{T("chg.newguide")}</li>')
                if gd.get("removed_guide"):
                    out.append(f'<li class="chg-rm">{T("chg.removedguide")}</li>')
                for h in gd["added"]:
                    out.append(f'<li><span class="chg-add">+</span> {inline_md(h)}</li>')
                for h in gd["removed"]:
                    out.append(f'<li><span class="chg-rm">−</span> {inline_md(h)}</li>')
                for h in gd["changed"]:
                    out.append(f'<li><span class="chg-chg">~</span> {inline_md(h)} — {T("chg.updated")}</li>')
                out.append("</ul>")
        out.append("</div>")
    out.append("</section>")
    return "".join(out)


def build_page(src, ui, version, date, is_draft, changelog_entries, since, releases, out_path: Path, base_prefix: str):
    """Render one complete page (all languages embedded; JS shows one)."""
    T = ML(ui)
    schemas = src["schemas"]
    i18n = src["i18n"]
    flat = {sid: flatten(e["schema"], sid) for sid, e in schemas.items()}
    rules = {sid: collect_rules(e["schema"], sid) for sid, e in schemas.items()}

    # Guides: each available source language rendered once; languages without a translation share the default one
    guide_html, guide_toc = {}, {}
    for g_lang, md_text in src["guides"].items():
        guide_html[g_lang], guide_toc[g_lang] = render_guide(md_text, f"g-{g_lang}")
    guide_src = {l: (l if l in src["guides"] else (DEFAULT_LANG if DEFAULT_LANG in src["guides"] else None)) for l in LANGS}
    guide_groups = {}
    for l, g in guide_src.items():
        if g:
            guide_groups.setdefault(g, []).append(l)

    ver_label = f"v{version}" + (" · DRAFT" if is_draft else "")

    # --- sidebar nav (guide TOC differs per source language; the rest is shared)
    nav = []
    nav.append(f'<h4>{T("nav.guide")}</h4>')
    for g, langs in guide_groups.items():
        nav.append(f'<div data-lang="{" ".join(langs)}">')
        for idx, (level, title, sid) in enumerate(guide_toc[g]):
            if idx == 0 and level == 1:  # document title, not a section
                continue
            nav.append(f'<a class="l{level}" href="#{sid}">{inline_md(title)}</a>')
        nav.append("</div>")
    nav.append(f'<h4>{T("nav.schemas")}</h4>')
    for sid, e in schemas.items():
        nav.append(f'<a class="l1" href="#schema-{sid}">{i18n_text(i18n, f"{sid}#title", e["schema"].get("title", sid))}</a>')
    nav.append(f'<h4>{T("nav.history")}</h4>')
    nav.append(f'<a class="l1" href="#changelog">{T("nav.changelog")}</a>')
    nav.append(f'<a class="l1" href="#versions">{T("nav.versions")}</a>')

    # --- main
    body = []
    if is_draft:
        body.append(f'<div class="draft-banner"><b>{T("draft")}</b> — {T("draft.hint")}</div>')
    for g, langs in guide_groups.items():
        others = [l for l in langs if l != g]
        if others:
            body.append(f'<div class="card meta" data-lang="{" ".join(others)}">{T("guide.fallback")} ({g.upper()})</div>')
        body.append(f'<section class="block md" data-lang="{" ".join(langs)}" id="guide-{g}">{guide_html[g]}</section>')
    body.append(f'<h1 id="schemas">{T("nav.schemas")}</h1><p class="meta">{T("schemas.intro")}</p>')
    for sid, e in schemas.items():
        body.append(render_schema_section(e, flat[sid], rules[sid], i18n, T, since, version))
    body.append(render_changelog(changelog_entries, T))
    body.append(f'<section class="block" id="versions"><h2>{T("nav.versions")}</h2><table><thead><tr><th>{T("col.version")}</th><th>{T("col.date")}</th><th>{T("col.note")}</th><th></th></tr></thead><tbody>')
    for r in reversed(releases):
        cur = f' ({T("current")})' if (r["version"] == version and not is_draft) else ""
        body.append(f'<tr><td><code>v{esc(r["version"])}</code>{cur}</td><td>{esc(r["meta"].get("date", ""))}</td><td>{inline_md(r["meta"].get("note", ""))}</td>'
                    f'<td><a href="{base_prefix}versions/{esc(r["version"])}/index.html">{T("open")}</a> · <a href="{base_prefix}schemas/{esc(r["version"])}/">{T("schemas.dir")}</a></td></tr>')
    if not releases:
        body.append(f'<tr><td colspan="4" class="meta">{T("versions.none")}</td></tr>')
    body.append("</tbody></table></section>")

    title = T.t(DEFAULT_LANG, "site.title")
    lang_buttons = "".join(f'<button data-set="{l}">{l.upper()}</button>' for l in LANGS)
    page = f"""<!doctype html>
<html lang="{DEFAULT_LANG}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} — {esc(ver_label)}</title>
<meta name="description" content="UzCORE / nSOC telemetry schemas, field reference and submission guide. {esc(ver_label)}">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%230f5fd1'/%3E%3Ctext x='16' y='22' font-size='16' text-anchor='middle' fill='white' font-family='sans-serif' font-weight='700'%3E{{}}%3C/text%3E%3C/svg%3E">
<style>{CSS}</style>
</head>
<body>
<header class="top">
  <button class="burger" aria-label="menu">☰</button>
  <span class="brand">{T("site.title")}</span>
  <span class="ver{' draft' if is_draft else ''}" title="{esc(date)}">{esc(ver_label)}</span>
  <span class="spacer"></span>
  <input id="q" type="search" aria-label="search" data-ph='{esc(json.dumps({l: T.t(l, "search.placeholder") for l in LANGS}, ensure_ascii=False))}'>
  <span id="qstatus" class="meta" data-labels='{esc(json.dumps({l: T.t(l, "search.hits") for l in LANGS}, ensure_ascii=False))}'></span>
  <span class="lang">{lang_buttons}</span>
  <span class="theme"><button title="theme">◐</button></span>
</header>
<div class="layout">
<nav class="side">{''.join(nav)}</nav>
<main>{''.join(body)}</main>
</div>
<footer>{esc(title)} · {esc(ver_label)} · {esc(date)} · built {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</footer>
<script>{JS % {'langs': json.dumps(LANGS), 'default': json.dumps(DEFAULT_LANG)}}</script>
</body></html>"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(page, encoding="utf-8")
    return len(page)


# ----------------------------------------------------------------------------- orchestration
def compute_since(release_sources):
    """pointer-key -> first version where the field appeared."""
    since = {}
    for ver, src in release_sources:
        for sid, e in src["schemas"].items():
            for r in flatten(e["schema"], sid):
                since.setdefault(f"{sid}#{r['pointer']}", ver)
    return since


def build(check_only=False):
    ui = load_json(I18N / "ui.json")
    releases = list_releases()
    release_sources = [(r["version"], load_sources(r["dir"])) for r in releases]
    working = load_sources(ROOT)

    # changelog entries (newest first)
    entries = []
    prev = None
    for (ver, src), r in zip(release_sources, releases):
        entries.append({"version": ver, "date": r["meta"]["date"], "note": r["meta"].get("note", ""),
                        "diff": diff_sources(prev, src) if prev else None, "is_draft": False})
        prev = src
    latest_ver = releases[-1]["version"] if releases else "0.0.0"
    latest_date = releases[-1]["meta"]["date"] if releases else datetime.date.today().isoformat()
    unreleased = diff_sources(prev, working) if prev else None
    is_draft = bool(prev) and not diff_is_empty(unreleased)
    if not prev:
        is_draft = True
    if is_draft:
        entries.append({"version": "unreleased", "date": datetime.date.today().isoformat(), "note": "",
                        "diff": unreleased, "is_draft": True})
    entries.reverse()

    # since: releases + working copy (as "draft" if new)
    since_src = release_sources + ([("draft", working)] if is_draft else [])
    since = compute_since(since_src)
    # fields that first appear in the very first release don't need a badge
    first_ver = release_sources[0][0] if release_sources else None
    since = {k: v for k, v in since.items() if v != first_ver}

    if check_only:
        print(f"releases: {[r['version'] for r in releases]}")
        print("unreleased changes:" if is_draft else "working copy == last release")
        if is_draft and unreleased:
            print(json.dumps({"schemas": {k: {kk: (len(vv) if isinstance(vv, list) else vv) for kk, vv in v.items()} for k, v in unreleased["schemas"].items()},
                              "guide": unreleased["guide"]}, ensure_ascii=False, indent=2))
        return

    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir()
    (DIST / ".nojekyll").write_text("")

    # latest page = working copy
    size = build_page(working, ui, latest_ver, latest_date, is_draft, entries, since, releases, DIST / "index.html", "")
    # schema files for working copy under latest version label
    sd = DIST / "schemas" / latest_ver
    sd.mkdir(parents=True)
    for e in working["schemas"].values():
        (sd / e["file"]).write_text(e["raw"], encoding="utf-8")
    (sd / "index.html").write_text("<!doctype html><meta charset=utf-8><ul>" + "".join(f'<li><a href="{e["file"]}">{e["file"]}</a></li>' for e in working["schemas"].values()) + "</ul>", encoding="utf-8")
    print(f"dist/index.html  v{latest_ver}{' (DRAFT)' if is_draft else ''}  {size/1024:.0f} KB")

    # archived versions: each built as it was at that release, with the changelog up to that point
    for i, ((ver, src), r) in enumerate(zip(release_sources, releases)):
        sub_entries = [e for e in entries if not e["is_draft"] and version_key(e["version"]) <= version_key(ver)]
        sub_since = {k: v for k, v in compute_since(release_sources[: i + 1]).items() if v != first_ver}
        build_page(src, ui, ver, r["meta"]["date"], False, sub_entries, sub_since, releases[: i + 1],
                   DIST / "versions" / ver / "index.html", "../../")
        vd = DIST / "schemas" / ver
        if not vd.exists():
            vd.mkdir(parents=True)
            for e in src["schemas"].values():
                (vd / e["file"]).write_text(e["raw"], encoding="utf-8")
            (vd / "index.html").write_text("<!doctype html><meta charset=utf-8><ul>" + "".join(f'<li><a href="{e["file"]}">{e["file"]}</a></li>' for e in src["schemas"].values()) + "</ul>", encoding="utf-8")
        print(f"dist/versions/{ver}/index.html")


def validate():
    ok = True
    for p in SCHEMAS.glob("*.schema.json"):
        try:
            load_json(p)
        except Exception as ex:
            ok = False
            print(f"INVALID JSON: {p.name}: {ex}")
    for p in I18N.glob("*.json"):
        try:
            load_json(p)
        except Exception as ex:
            ok = False
            print(f"INVALID JSON: {p.name}: {ex}")
    try:
        import jsonschema  # optional
        for p in SCHEMAS.glob("*.schema.json"):
            jsonschema.Draft202012Validator.check_schema(load_json(p))
    except ImportError:
        print("(jsonschema not installed; skipping meta-schema check)")
    except Exception as ex:
        ok = False
        print(f"SCHEMA ERROR: {ex}")
    # i18n coverage: only fields that actually carry a description need a translation
    keys, described = set(), set()
    for p in SCHEMAS.glob("*.schema.json"):
        sid = schema_id_from_file(p)
        sc = load_json(p)
        for k, has in ((f"{sid}#title", bool(sc.get("title"))), (f"{sid}#description", bool(sc.get("description")))):
            keys.add(k)
            if has:
                described.add(k)
        for r in flatten(sc, sid):
            keys.add(f"{sid}{r['pointer']}")
            if r["description"]:
                described.add(f"{sid}{r['pointer']}")
    for lang in LANGS:
        if lang == DEFAULT_LANG:
            continue
        p = I18N / f"schema.{lang}.json"
        tr = load_json(p) if p.exists() else {}
        stale = [k for k in tr if k not in keys]
        missing = [k for k in sorted(described) if k not in tr]
        if stale:
            print(f"i18n/schema.{lang}.json: {len(stale)} stale key(s) (field no longer exists): " + ", ".join(stale[:5]) + (" …" if len(stale) > 5 else ""))
        if missing:
            print(f"i18n/schema.{lang}.json: {len(missing)} description(s) not translated (shown in UZ): " + ", ".join(missing[:5]) + (" …" if len(missing) > 5 else ""))
        else:
            print(f"i18n/schema.{lang}.json: complete")
    return ok


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "release":
        if len(args) < 2:
            sys.exit("usage: build.py release <version> [note]")
        if not validate():
            sys.exit(1)
        make_release(args[1], " ".join(args[2:]))
        build()
    elif args and args[0] == "check":
        ok = validate()
        build(check_only=True)
        sys.exit(0 if ok else 1)
    else:
        if not validate():
            sys.exit(1)
        build()
