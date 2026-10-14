# National SOC (UzCORE) — Technical guide for data submission

**Version:** 1.0
**Date:** 2026-09-28
**Status:** For distribution to organizations
**Standards:** OCSF 1.9.0 (Detection Finding 2004 + Incident Finding 2005) · ENISA RSIT 1.3 · EU NIS 2 taxonomy · MITRE ATT&CK · CVE / CPE 2.3 · TLP 2.0 · O'zMSt 816:2025 · O'zMSt ISO/IEC 27005:2024 · O'z DSt 2814:2014 · ISO 8601 · RFC 4122 (UUID)

---

## 0. About this document

### 0.1 Data submission

The sample JSON data presented below in this document is intended to be sent directly via the API.


### 0.2 Types of data submitted

UzCORE accepts the following types of data from organizations:

| # | Telemetry | Source system | Submission mode | Confidentiality |
|---|---|---|---|---|
| 1 | **Incident Report** — a confirmed security incident | SOAR / Case management (TheHive, XSOAR, Sentinel, QRadar SOAR) | When the incident is opened + on every significant update | Per TLP, usually AMBER |
| 2 | **Alert** — a detection by a single tool | SIEM / EDR / IDS (Wazuh, Splunk, Elastic) | Real time or batch (≤5 minutes) | AMBER |
| 3 | **Asset Inventory** — list of assets | SIEM / inventory tool | Periodic snapshot (once a day) | **TLP:RED** |


---

## 1. General technical rules

### 1.1 Transport and endpoints

All requests: `HTTPS`, `Content-Type: application/json`, `UTF-8` encoding.

| Method | Endpoint | What it does |
|---|---|---|
| `GET` | `/connector/me` | Returns the organization profile of the authenticated subject |
| `POST` | `/connector/bulk-incidents` | Submit a batch of incident reports |
| `POST` | `/connector/bulk-alerts` | Submit a batch of alerts |
| `POST` | `/connector/bulk-assets` | Submit an asset snapshot |


### 1.2 Authentication — HMAC-SHA256 signature

Every request is **signed locally with a secret key**, and the key itself never leaves your side over the network.

#### 1.2.1 Registering the organization

Contact the Cybersecurity Center administration and obtain two values for your organization:

| Value | Purpose |
|---|---|
| `organizationId` | Identifies your organization. Sent in every request via the `x-org-id` header. |
| `key` | Secret key. **Never sent to the server** — it stays only on your side and is used to sign requests locally. |

#### 1.2.2 Storing the data

`key` is a password-grade secret:

- It is not hard-coded and does not end up in Git.
- It is stored in an environment variable, a secret manager or an encrypted configuration file.
- If stored in a file, the permissions are `0600`.
- It is not written to logs, error messages or traces.

If you suspect the key has leaked, you are asked to contact the Cybersecurity Center immediately.

#### 1.2.3 Signing the request

Every request is signed with HMAC-SHA256.

| Header | Value |
|---|---|
| `x-org-id` | `organizationId` |
| `x-timestamp` | Request time, in epoch seconds |
| `x-nonce` | Random string per request (against replay attacks) |
| `x-signature` | HMAC-SHA256 result, lowercase hex |


**Python:**

```python
import hashlib, hmac, json, os, secrets, time
import requests

ORG_ID = os.environ["UZCORE_ORG_ID"]
KEY    = os.environ["UZCORE_KEY"].encode()
BASE   = os.environ["UzCORE_BASE_URL"]

def send(method: str, path: str, payload=None):
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode() if payload is not None else b""
    ts    = str(int(time.time()))
    nonce = secrets.token_hex(8)
    body_hash = hashlib.sha256(body).hexdigest()

    canonical = "\n".join([method.upper(), path, ts, nonce, body_hash])
    signature = hmac.new(KEY, canonical.encode(), hashlib.sha256).hexdigest()

    return requests.request(
        method, BASE + path, data=body,
        headers={
            "Content-Type": "application/json",
            "x-org-id":     ORG_ID,
            "x-timestamp":  ts,
            "x-nonce":      nonce,
            "x-signature":  signature,
        },
        timeout=30,
    )
```

#### 1.2.4 Verification and go-live

Validate the integration **before** sending real data:

```
GET /connector/me
```

If the signature is correct, the server returns your organization profile. Any other response means there is an error in the headers or in the signature itself.


### 1.3 `org_id` — the most common place for mistakes

Every record carries **two identifiers**, and they do not have to be the same:

| Place | Field | Meaning |
|---|---|---|
| HTTP header | `x-org-id` | **Who sent it** — the authenticated organization. Usually a regional SOC or an MSSP. |
| Payload body | `org_id` | **Who it is about** — the organization where the incident occurred or to which the data belongs. |

The backend separates the two as follows: the signature is verified against `x-org-id`, while the data is recorded under the `org_id` in the body. **`sender_id` is not sent in the body** — the sender is already identified via the header and the signature.

Three scenarios:

```
1. The organization sends on its own behalf:
   header  x-org-id = org-A
   body    org_id   = org-A            ← both identical

2. A sectoral SOC sends on behalf of a member:
   header  x-org-id = sector-soc-finance
   body    org_id   = org-bank-014     ← different

3. An MSSP sends on behalf of a client:
   header  x-org-id = mssp-alpha
   body    org_id   = org-clinic-007   ← different
```

**Separate requirement for MSSPs:** data of several clients is not mixed in a single payload. A separate request is sent for each `org_id`. Mixed (non-attributable) data is rejected.

### 1.4 Time formats — ATTENTION, two different ones

| Telemetry | Format | Example |
|---|---|---|
| Incident Report | **ISO 8601**, UTC, with `Z` | `"2026-08-13T09:12:44Z"` |
| Asset Inventory | **ISO 8601**, UTC, with `Z` | `"2026-08-13T02:00:00Z"` |
| Alert — `collected_at` | **ISO 8601**, UTC | `"2026-08-13T09:15:00Z"` |
| Alert — OCSF internal fields (`time`, `start_time`, `end_time`, `metadata.logged_time`) | **epoch milliseconds** (integer) | `1786594364512` |

Conversion:

```python
# ISO -> epoch ms
import datetime
dt = datetime.datetime(2026, 8, 13, 4, 12, 44, 512000, tzinfo=datetime.timezone.utc)
epoch_ms = int(dt.timestamp() * 1000)   # 1786594364512

# epoch ms -> ISO
datetime.datetime.fromtimestamp(1786594364512/1000, datetime.timezone.utc).isoformat()
```

### 1.5 Idempotency and `report_id` generation

If the network drops or no response arrives, **resend exactly the same payload**. 

| Telemetry | Idempotency key |
|---|---|
| Incident | `report_id` |
| Alert | `org_id` + `metadata.product.name` + `finding_info.uid` |
| Asset | `org_id` + `asset_uid` (upsert, §4.2) |


#### 1.5.1 Deterministic UUID v5

**`report_id` is not stored; it is recomputed every time.** If the input data is the same, the result is always the same.

UUID v5 (RFC 4122 §4.3) is a name-based, deterministic UUID using SHA-1.

```
report_id = uuidv5(UzCORE_NAMESPACE, org_id + "|" + source_case_id)
```

**UzCORE namespace UUID (the same for all organizations, does not change):**

```
17e9f2a9-2473-5a70-b622-f121ae871cb0
```

**Worked example:**

```
org_id          = b3f1c2a4-1d2e-4f56-9abc-1234567890ab
source_case_id  = CASE-2026-0441
nom satri       = "b3f1c2a4-1d2e-4f56-9abc-1234567890ab|CASE-2026-0441"

report_id       = 8f339179-64ae-5763-99ab-2a0c6562203e
```

Another case:

```
"b3f1c2a4-1d2e-4f56-9abc-1234567890ab|CASE-2026-0442"
  → 99a3488d-1523-5499-85e7-afa2a6595466
```

**Python:**

```python
import uuid

UzCORE_NS = uuid.UUID("17e9f2a9-2473-5a70-b622-f121ae871cb0")

def make_report_id(org_id: str, source_case_id: str) -> str:
    name = f"{org_id.strip().lower()}|{source_case_id.strip()}"
    return str(uuid.uuid5(UzCORE_NS, name))

make_report_id("b3f1c2a4-1d2e-4f56-9abc-1234567890ab", "CASE-2026-0441")
# '8f339179-64ae-5763-99ab-2a0c6562203e'
```


#### 1.5.2 Normalization rules — required

Determinism works only when the input string is identical **character by character**:

| Rule | Reason |
|---|---|
| `org_id` — converted to lowercase, whitespace stripped | UUIDs are sometimes written in uppercase |
| `source_case_id` — only whitespace stripped, **case is not changed** | Case IDs are case-sensitive (`CASE-441` ≠ `case-441`) |
| Separator — always `\|` (vertical bar) | `-` or `:` may occur inside a case ID |

#### 1.5.3 For this reason `source_case_id` is REQUIRED

Every SOAR/case system has this value:

| System | Field |
|---|---|
| TheHive | `case.caseId` or `case._id` |
| Cortex XSOAR | `incident.id` |
| Microsoft Sentinel | `incident.properties.incidentNumber` |
| Splunk SOAR | `container.id` |
| IBM QRadar SOAR | `incident.id` |
| ServiceNow SecOps | `sn_si_incident.number` |


### 1.6 Response codes and error format

UzCORE returns errors according to the **RFC 9457 (Problem Details for HTTP APIs)** standard.

Response header: `Content-Type: application/problem+json`

**Standard fields (RFC 9457 §3.1):**

| Field | Description |
|---|---|
| `type` | URI identifying the problem type. For UzCORE: `https://uzcore.csec.uz/problems/<slug>` |
| `title` | Short, human-readable title. Does not change for the same `type`. |
| `status` | HTTP status code (the same as the code in the response) |
| `detail` | Explanation specific to this occurrence |
| `instance` | URI identifying this specific request |

**UzCORE extension (extension member):** the `errors[]` array — a separate error for each field. RFC 9457 §3.2 allows extension members.

The structure of an array element matches the JSON Schema 2020-12 standard output format:

| Field | Description |
|---|---|
| `pointer` | **RFC 6901 JSON Pointer** — the exact location of the problematic field in the payload |
| `code` | Machine-readable error code |
| `detail` | Explanation |
| `allowed` | For enum errors — the list of allowed values |

**Example — `422`:**

```json
{
  "type": "https://uzcore.csec.uz/problems/validation-failed",
  "title": "Payload failed schema validation",
  "status": 422,
  "detail": "2 ta maydon validatsiyadan o'tmadi.",
  "instance": "/connector/bulk-incidents#req-01J8XK3P2",
  "errors": [
    {
      "pointer": "/classification/event_type",
      "code": "enum_mismatch",
      "detail": "'ransomware' qiymati 'malicious_code' kategoriyasi uchun to'g'ri RSIT event_type emas.",
      "allowed": ["infected_system", "c2_server", "malware_distribution", "malware_configuration"]
    },
    {
      "pointer": "/lifecycle/detected_at",
      "code": "required",
      "detail": "Maydon majburiy."
    }
  ]
}
```

**The `pointer` for an element inside an array** includes the array index:

```json
{
  "pointer": "/assets/12/technical/known_cves/0/cve_id",
  "code": "format_invalid",
  "detail": "CVE identifikatori 'CVE-YYYY-NNNN+' formatida, katta harflarda bo'lishi kerak."
}
```

**Error codes (`code`):**

| Code | Meaning |
|---|---|
| `required` | Required field is missing |
| `enum_mismatch` | Value is not in the allowed list |
| `type_mismatch` | Wrong data type (e.g. integer instead of string) |
| `format_invalid` | Malformed format (UUID, ISO 8601, CVE, CPE) |
| `out_of_range` | Number is outside the allowed range |
| `too_long` | String or array exceeds the limit |
| `unknown_field` | Field not in the schema (`additionalProperties: false`) |
| `conditional_required` | A field that became required because a condition was met is missing |
| `cross_field_conflict` | Fields contradict each other (e.g. `detected_at` > `opened_at`) |
| `forbidden_field` | Field that is forbidden to send (`metadata.tenant_uid`) |


### 1.7 TLP 2.0 — confidentiality level

Every record carries a `tlp` value. UzCORE uses this value to decide who may see it and how it is distributed.

| Value | Meaning | When it is used |
|---|---|---|
| `CLEAR` | Distributed without restriction | Public information |
| `GREEN` | Within the community | IOCs, so that other organizations can protect themselves |
| `AMBER` | Only the organization and its clients | Default case — most incidents |
| `AMBER+STRICT` | Only within the organization | Sensitive incidents |
| `RED` | Only named recipients | Asset inventory (required) |

`AMBER` for incidents, `RED` for asset inventory (required; no other value is accepted).

---

# 2. Incident Report — confirmed incident

## 2.1 Definition

A confirmed security incident for which a **case has been opened** in the organization's SOAR / case-management system. This is not a tool's signal — it is an incident that an analyst has reviewed, confirmed as genuine, and for which response actions have begun.

**Source:** TheHive, Cortex XSOAR, Microsoft Sentinel, Splunk SOAR (Phantom), IBM QRadar SOAR, ServiceNow SecOps.

## 2.2 When it is sent

An incident is sent **several times** over its lifetime, and the **same `report_id`** is used every time:

```
  Case opened           →  status_id: 1 (New)
  Investigation started →  status_id: 2 (In Progress)
  Waiting for vendor    →  status_id: 3 (On Hold)
  Resolved              →  status_id: 4 (Resolved)
  Closed                →  status_id: 5 (Closed)  +  closed_at
```

Whether this is the first submission or an update is **not flagged separately**. The server determines it by `report_id`: if it exists in the database, it is an update; if not, it is a new incident.

**Cases where sending an update is required:**
- `lifecycle.status_id` changed
- `classification.severity_id` changed
- `lifecycle.verdict_id` was set or changed
- A new IOC or a new affected asset was added
- `response.containment_status` changed

For other minor changes, sending an update is not required.

**Deadline:** incidents of `critical` and `high` severity are sent **within 1 hour** of detection, the rest **within 24 hours**.

## 2.3 Full JSON example

The envelope carries `org_id` once; incidents are in the `incidents[]` array. Below is a batch with a single incident:

```json
{
  "telemetry_type": "incident_batch",
  "schema_version": "1.0",
  "org_id": "b3f1c2a4-1d2e-4f56-9abc-1234567890ab",
  "collected_at": "2026-08-13T06:20:00Z",
  "incidents": [
    {
      "report_id": "8f339179-64ae-5763-99ab-2a0c6562203e",
      "source_case_id": "CASE-2026-0441",
      "source_system": "TheHive",
      "tlp": "AMBER",
      "lifecycle": {
        "status_id": 2,
        "detected_at": "2026-08-13T03:42:00Z",
        "opened_at": "2026-08-13T03:50:00Z",
        "updated_at": "2026-08-13T06:20:00Z",
        "closed_at": null,
        "time_to_acknowledge_sec": 480,
        "time_to_contain_sec": 9000,
        "time_to_resolve_sec": null,
        "verdict_id": 2
      },
      "classification": {
        "event_category": "malicious_code",
        "event_type": "infected_system",
        "title": "Internetga ochiq serverda shifrlovchi zararli dastur",
        "description": "Yamoqlanmagan web-xizmatni ekspluatatsiya qilgandan keyin fayllarni shifrlash faoliyati aniqlandi. Ikki server ta'sirlangan, izolyatsiya qilindi.",
        "severity_id": 5
      },
      "technical": {
        "mitre_attacks": [
          {
            "tactic": {
              "uid": "TA0001",
              "name": "Initial Access"
            },
            "techniques": [
              {
                "uid": "T1190",
                "name": "Exploit Public-Facing Application"
              }
            ]
          },
          {
            "tactic": {
              "uid": "TA0006",
              "name": "Credential Access"
            },
            "techniques": [
              {
                "uid": "T1110",
                "name": "Brute Force",
                "sub_techniques": [
                  {
                    "uid": "T1110.001",
                    "name": "Password Guessing"
                  },
                  {
                    "uid": "T1110.003",
                    "name": "Password Spraying"
                  }
                ]
              },
              {
                "uid": "T1003",
                "name": "OS Credential Dumping",
                "sub_techniques": [
                  {
                    "uid": "T1003.001",
                    "name": "LSASS Memory"
                  }
                ]
              },
              {
                "uid": "T1555",
                "name": "Credentials from Password Stores"
              }
            ]
          },
          {
            "tactic": {
              "uid": "TA0010",
              "name": "Exfiltration"
            },
            "techniques": [
              {
                "uid": "T1041",
                "name": "Exfiltration Over C2 Channel"
              }
            ]
          },
          {
            "tactic": {
              "uid": "TA0040",
              "name": "Impact"
            },
            "techniques": [
              {
                "uid": "T1486",
                "name": "Data Encrypted for Impact"
              }
            ]
          }
        ],
        "affected_asset_uids": [
          "web014",
          "web015"
        ],
        "indicators": [
          {
            "type": "ipv4",
            "value": "203.0.113.55"
          },
          {
            "type": "sha256",
            "value": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
          },
          {
            "type": "domain",
            "value": "update-cdn-node7.example"
          }
        ]
      },
      "alerts": [
        "wazuh-1691-abc",
        "wazuh-1692-def",
        "wazuh-1703-ghi"
      ],
      "response": {
        "actions_taken": [
          "host isolated from network",
          "C2 IP blocked at perimeter",
          "credentials reset for affected service accounts"
        ],
        "containment_status": "contained"
      },
      "related_report_ids": [],
      "activity": [
        {
          "time": "2026-08-13T03:50:00Z",
          "type": "case_opened"
        },
        {
          "time": "2026-08-13T03:58:00Z",
          "type": "status_changed",
          "to_status_id": 2
        },
        {
          "time": "2026-08-13T04:10:00Z",
          "type": "task_created"
        },
        {
          "time": "2026-08-13T04:22:00Z",
          "type": "comment_added"
        },
        {
          "time": "2026-08-13T04:35:00Z",
          "type": "task_completed"
        },
        {
          "time": "2026-08-13T05:05:00Z",
          "type": "artifact_added"
        },
        {
          "time": "2026-08-13T06:20:00Z",
          "type": "severity_changed",
          "to_severity_id": 5
        }
      ]
    }
  ]
}
```

## 2.4 Fields

### 2.4.1 Field marking system

Every field table has an `R/O` column:

| Marker | Meaning |
|---|---|
| **R** | **Required** — mandatory. Without this field the payload is rejected with `422`. |
| **C** | **Conditional** — conditionally required. When it is required is stated in the field's description. |
| **O** | **Optional** — optional. Sent if the organization has this data. |
| **R\*** | Required for each element **inside** an array. The array itself may be optional. |
| **STD** | The value is taken **from a standard catalog** (OCSF, RSIT, MITRE, CVE). It is not invented. The lists are in the appendices. |

### 2.4.2 References to standards

| Standard | Version | Owner | Where to look |
|---|---|---|---|
| **OCSF** (Open Cybersecurity Schema Framework) | 1.9.0 | Linux Foundation | `https://schema.ocsf.io/1.9.0/` |
| **ENISA RSIT** (Reference Security Incident Taxonomy) | 1.3 | ENISA / TF-CSIRT | `https://github.com/enisaeu/Reference-Security-Incident-Taxonomy-Task-Force` |
| **EU NIS 2** impact taxonomy | — | NIS Cooperation Group | For the impact block |
| **MITRE ATT&CK** | Enterprise v15+ | MITRE | `https://attack.mitre.org/` |
| **CVE** | — | MITRE / NVD | `https://nvd.nist.gov/` |
| **CPE** | 2.3 | NIST | `https://nvd.nist.gov/products/cpe` |
| **TLP** | 2.0 | FIRST | `https://www.first.org/tlp/` |


### 2.4.3 Envelope — who and when

These fields apply to the **entire batch** and are written once. The backend checks delegation by exactly this `org_id` — a single check, regardless of how many hundreds of incidents are in the array.

| Field | Type | R/O | Definition and allowed values |
|---|---|---|---|
| `telemetry_type` | string | **R** | Fixed value: `"incident_batch"`. Routes the payload to the correct pipeline. |
| `schema_version` | string | **R** | Version of this document. Currently: `"1.0"`. |
| `org_id` | UUID | **R** | The organization where the incidents occurred — the **data owner** (§1.3). One organization per request. |
| `collected_at` | timestamp | **O** | Time the batch was assembled by the integration. **ISO 8601 UTC.** Diagnostic field — see the note below. |
| `incidents` | array | **R** | 1–200 incident objects |

**Why `collected_at` is needed and how it is used:**

This field provides information not about the incident but **about the integration**. It has two practical purposes:

| Purpose | How it is calculated | What it shows |
|---|---|---|
| Delivery latency | `collected_at − lifecycle.updated_at` | How much time passed between the case being updated in the SOAR and reaching UzCORE. A large gap indicates the connector has slowed down or is stuck in a queue. |
| Integration liveness signal | The latest `collected_at` value | Shows when the organization's integration last worked — even on days with no incidents. |

If left empty, UzCORE uses the time the request was received. That also works, but with lower accuracy: it includes network latency and server queueing, meaning a connector problem cannot be distinguished from a network problem.

### 2.4.4 `incidents[]` element — identification

| Field | Type | R/O | Definition and allowed values |
|---|---|---|---|
| `report_id` | UUID v5 | **R\*** | Stable identifier of the incident. **Computed by the formula in §1.5**, not randomly generated. Does not change over the incident's lifetime. |
| `source_case_id` | string | **R\*** | The organization's own case number. **`report_id` is derived from it (§1.5), hence it is required.** Does not change over the incident's lifetime. |
| `source_system` | string | **O** | Name of the case system: `"TheHive"`, `"XSOAR"`, `"Sentinel"`, `"Splunk SOAR"`, `"QRadar SOAR"`, `"Updive"`. |
| `tlp` | enum | **R\*** | `CLEAR` │ `GREEN` │ `AMBER` │ `AMBER+STRICT` │ `RED`. Typical value: `AMBER`. |
| `related_report_ids` | array[UUID] | **O** | The `report_id`s of **other incidents the analyst considers related** to this one. Details: below. |
| `alerts` | array[string] | **O** | The `finding_info.uid` values of the alerts linked to this incident. Location: **directly in** the `incidents[]` element, at the same level as the `lifecycle` and `technical` blocks. Links to alert telemetry and opens the CVE chain. |

**`related_report_ids` — when it is used:**

This field is filled **only** when the analyst considers two separate cases to be related to each other. Typical situations:

- One attack was opened in two cases (duplicate), one was merged into the other
- Several stages of one campaign were observed in separate cases
- A new incident arose because the previous one was not fully closed

```json
{
  "report_id": "99a3488d-1523-5499-85e7-afa2a6595466",
  "source_case_id": "CASE-2026-0442",
  "related_report_ids": ["8f339179-64ae-5763-99ab-2a0c6562203e"],
  "lifecycle": {
    "status_id": 5,
    "verdict_id": 10,
    "closed_at": "2026-08-14T09:00:00Z"
  }
}
```

In this example, `verdict_id: 10` (Duplicate) states that the incident is a duplicate, while `related_report_ids` states **which** incident it duplicates. The two work together: UzCORE excludes the duplicate from national statistics but preserves the link.

### 2.4.5 `lifecycle` — incident lifetime and response speed

| Field | Type | R/O | Definition and allowed values |
|---|---|---|---|
| `detected_at` | timestamp | **R\*** | Time the organization's tool **first detected** the activity — not the time the case was opened. Usually the time of the earliest alert. The starting point for all `time_to_*` calculations. |
| `opened_at` | timestamp | **R\*** | Time the case was opened in the SOAR. `opened_at − detected_at` = triage delay. |
| `updated_at` | timestamp | **R\*** | Time this specific version of the report was produced. Changes with every update. |
| `closed_at` | timestamp | **C** | Time the case was closed. **Required when `status_id` = `5`.** Otherwise `null`. |
| `time_to_acknowledge_sec` | integer | **O** | MTTA: from `detected_at` to the first analyst action, in seconds. |
| `time_to_contain_sec` | integer | **O** | MTTC: from `detected_at` to containment, in seconds. |
| `time_to_resolve_sec` | integer | **O** | MTTR: from `detected_at` to full resolution, in seconds. |
| `verdict_id` | integer | **O · STD** | Conclusion after investigation. Full list and mapping: **Appendix B.6**. |

> A case is always in one of these five states. If the source system's state is not in the list, choose the closest match from the **Appendix B.5** table.

**`time_to_*_sec` — calculation rule:**

All three values are calculated **from `detected_at`**, not from `opened_at`. This rule is mandatory: if organizations use different starting points, the national MTTR metric becomes incomparable.

```
time_to_acknowledge_sec = birinchi_analitik_harakati − detected_at
time_to_contain_sec     = lokalizatsiya_vaqti      − detected_at
time_to_resolve_sec     = hal_qilingan_vaqt        − detected_at
```

The values are filled from SOAR data. If the system does not provide the required time, leave the field `null` — do not send an estimated value.

### 2.4.6 `classification` — incident type (ENISA RSIT)

| Field | Type | R/O | Definition and allowed values |
|---|---|---|---|
| `event_category` | enum | **R\* · STD** | RSIT first level — 10 values. Full list: **Appendix A**. |
| `event_type` | enum | **O · STD** | RSIT second level. **Must match the selected category.** Full list: **Appendix A**. |
| `title` | string | **R\*** | Short title, 3–120 characters. No confidential information. |
| `description` | string | **O** | Sanitized summary, ≤2000 characters. No IPs, usernames, command lines, or raw logs. |
| `severity_id` | integer | **R\* · STD** | `0` Unknown · `1` Informational · `2` Low · `3` Medium · `4` High · `5` Critical · `99` Other. **Same scale as alert telemetry.** |

> **Why `event_type` is optional:** no SOAR system has the RSIT taxonomy, meaning this value is always selected manually. Leaving it empty is better than choosing the wrong one of 35 types — the category-level picture in national statistics remains correct either way.

### 2.4.7 `technical` — attacker behavior

| Field | Type | R/O | Description and allowed values |
|---|---|---|---|
| `mitre_attacks` | array[object] | **O · STD** | MITRE ATT&CK tactics, with techniques under each, and sub-techniques under those. Structure below. |
| `affected_asset_uids` | array[string] | **O** | `asset_uid` values of the affected assets. Must be written exactly as `assets[].asset_uid` in the asset inventory. This field is the only way to link to assets. Filled in when the assets are known. If no internal asset was involved or the scope is not yet determined, `[]` is sent and filled in at the next lifecycle update. |
| `indicators` | array[object] | **R\*** | IOCs. Structure below. An empty array (`[]`) is allowed only when the source system has no observables at all. |

#### `affected_asset_uids` — hostname, not the SOAR asset ID

SOAR systems store the affected asset by their own internal record ID (for example FortiSOAR asset ID `a3f9…`). This ID is **not sent** to UzCORE: UzCORE has no such asset and the link would be lost. Instead, the **hostname** attribute of the SOAR asset is taken and normalized by the rule below.

**Normalization rule** — the same for the technical asset's `asset_uid`, `device.hostname` in the alert and `affected_asset_uids` in the incident:

1. Leading and trailing whitespace is removed.
2. Converted to lowercase.
3. If it is an FQDN, the part before the first dot is taken: `WEB01.corp.local` → `web01`.
4. An IP address is not written as a hostname.

**Where the hostname lives in the SOAR:**

| SOAR | Where the affected asset is | Where the hostname is taken from |
|---|---|---|
| TheHive | Observable | `dataType: hostname` |
| Cortex XSOAR | Incident field / indicator | `Hostname`, `Device Name` |
| Microsoft Sentinel | Entity `Host` | `HostName` (`DnsDomain` is not appended) |
| Splunk SOAR | Artifact (CEF) | `destinationHostName`, `deviceHostname` |
| IBM QRadar SOAR | Artifact | `System Name` |
| FortiSOAR | Assets module record | `hostname` field |

If the SOAR has only the IP address of the asset, it is not written to `affected_asset_uids` — the link is restored via `alerts[]`.

> **Protection on the UzCORE side.** UzCORE looks up the received value in two places: the asset's `asset_uid` and the normalized `technical.hostname`. In addition, if `affected_asset_uids` is empty or does not match, the asset is found via `alerts[]` → `device.hostname` in the alert. That is why it is important to write the SIEM alert IDs belonging to the incident into `alerts[]`.

**`indicators[]` element:**

| Field | Type | R/O | Description and allowed values |
|---|---|---|---|
| `type` | enum | **R\*** | `ipv4` │ `ipv6` │ `domain` │ `url` │ `md5` │ `sha1` │ `sha256` │ `email` │ `file_name` │ `user_agent` │ `registry_key` |
| `value` | string | **R\*** | Indicator value. Refanged, domains and hashes written in lowercase, RFC 1918 internal addresses are not sent. |

> An indicator consists of only two fields: **type and value**. `role`, `tlp` and `first_seen` are deliberately absent — the first does not exist in any SOAR and would arrive empty, the second is covered by the incident's `tlp`, and the third duplicates `lifecycle.detected_at`.

**`mitre_attacks[]` — three-level structure:**

```
mitre_attacks[]
 └── tactic                    (one tactic, required)
 └── techniques[]              (techniques under this tactic, at least one)
      └── sub_techniques[]     (sub-techniques under this technique, optional)
```

| Field | Type | R/O | Description and allowed values |
|---|---|---|---|
| `tactic` | object | **R\*** | Tactic. **Required** — a technique without a tactic is not sent. |
| `tactic.uid` | string | **R\* · STD** | Format: `TA####`. Example: `"TA0006"`. Full list: **Appendix B.9** |
| `tactic.name` | string | **O** | `"Credential Access"` |
| `techniques` | array | **R\*** | Techniques under this tactic. **At least one**, an empty array is rejected. |
| `techniques[].uid` | string | **R\* · STD** | Format: `T####`. Example: `"T1110"`. A sub-technique is not written here. |
| `techniques[].name` | string | **O** | `"Brute Force"` |
| `techniques[].sub_techniques` | array | **O** | Sub-techniques. If there are none, the field is omitted entirely. |
| `…sub_techniques[].uid` | string | **R\* · STD** | Format: `T####.###`. Example: `"T1110.001"` |
| `…sub_techniques[].name` | string | **O** | `"Password Guessing"` |

**Mandatory rules:**

- **A tactic appears once.** If there are several techniques under one tactic, they are listed inside `techniques[]` — the tactic is not repeated.
- **A sub-technique is not sent without its parent technique.** If the source system provides only `T1110.001`, the connector or the developer sending directly via the API derives the parent technique from the ID itself (`T1110`), writes it to `techniques[].uid`, and places the sub-technique in its `sub_techniques[]`.
- **The tactic is required.** If the source system has no tactic, it must be determined from the ATT&CK catalog. If one technique belongs to several tactics, the analyst selects the purpose for which it was used in the incident.
- **Duplicates are forbidden.** If the same `tactic.uid`, the same `techniques[].uid` or the same `sub_techniques[].uid` is written twice, the payload is rejected.

**Example — three techniques under one tactic, one of them with two sub-techniques:**

```json
{
  "tactic": { "uid": "TA0006", "name": "Credential Access" },
  "techniques": [
    {
      "uid": "T1110",
      "name": "Brute Force",
      "sub_techniques": [
        { "uid": "T1110.001", "name": "Password Guessing" },
        { "uid": "T1110.003", "name": "Password Spraying" }
      ]
    },
    {
      "uid": "T1003",
      "name": "OS Credential Dumping",
      "sub_techniques": [
        { "uid": "T1003.001", "name": "LSASS Memory" }
      ]
    },
    { "uid": "T1555", "name": "Credentials from Password Stores" }
  ]
}
```

> **Why is the tactic required?** The tactic **does not follow** from the technique — one technique can belong to several tactics. For example `T1078 Valid Accounts` appears in four tactics: Initial Access, Persistence, Privilege Escalation, Defense Evasion. If only the technique ID is sent, it is impossible to tell whether the attacker was gaining access, establishing persistence or escalating privileges.
>
> For this reason it is also normal for one technique to appear **under several tactics**: if the attacker used `T1078` first for access and then for persistence, it is written in both the `TA0001` and `TA0003` groups.

> **Difference from the alert:** in alert telemetry this information is stored, per the OCSF requirement, as **flat** pairs in `finding_info.attacks[]` (`{tactic, technique, sub_technique}`). The OCSF field structure cannot be changed. In the incident, the nested form is used — it expresses the full picture written by the analyst more precisely. The connector builds both forms.

> **No `kill_chain_phase`.** The Lockheed Martin kill-chain field is **not used at all** in this document — neither in the incident nor in the alert. ATT&CK tactics answer the same question more precisely (14 tactics instead of 7 phases), and keeping both fields together leads to contradictions — for example `kill_chain_phase: "delivery"` next to `tactic: TA0040 Impact`. The attack phase is expressed via `mitre_attacks[].tactic`. Full list of tactics: **Appendix B.9**.
>
### 2.4.8 `response` — what was done

| Field | Type | R/O | Description and allowed values |
|---|---|---|---|
| `actions_taken` | array[string] | **O** | Actions performed within the case, free text. Each ≤300 characters. |
| `containment_status` | enum | **O · STD** | Response phase: `not_contained` │ `partially_contained` │ `contained` │ `eradicated` │ `recovered` |
| `closing_note` | string | **O** | Free-text note at case closure, ≤2000 characters. |

> **No confidential information is written into `actions_taken` and `closing_note`.** Host name, IP address, user login, employee name, command line — none of them. Correct: `"Infected host was isolated"`. Incorrect: `"web014 (10.0.2.14) isolated, root account blocked"`.

**`containment_status` — NIST SP 800-61 response phases:**

| Value | Meaning |
|---|---|
| `not_contained` | Not contained, the attack is ongoing |
| `partially_contained` | Partially contained, some vectors remain open |
| `contained` | Contained, spread has been stopped |
| `eradicated` | Malicious component removed from the system |
| `recovered` | System returned to normal operation |

This field does **not duplicate** `lifecycle.status_id`: `status_id` reflects the workflow (who is working on it), while `containment_status` reflects the technical state (whether the attack has been stopped). An incident with `status_id: 2` (In Progress) may be contained or not — and the most urgent view for the operator is exactly the intersection of these two: **critical + not contained**.

**`closing_note` is not the closure reason.** The closure reason is written in structured form in `lifecycle.verdict_id` (Appendix B.6). `closing_note` is the free-text note alongside it: what was done, what was found.

### 2.4.9 `activity` — case chronology

All steps performed on the case in chronological order: opening, status changes, comments, tasks, closure and reopening. This data shows how the incident was handled — when the national operator reviews a serious incident, this is how they know what the organization did.

> **The task list is not sent separately.** The full list of tasks inside the case (title, assignee, status) is not transmitted to UzCORE. The chronology, however, keeps the `task_created` and `task_completed` events — that is, the **fact and time** that a task was created and completed are visible, but not its content. This is sufficient for measuring response pace and does not create a confidentiality risk.

| Field | Type | R/O | Description and allowed values |
|---|---|---|---|
| `time` | timestamp | **R\*** | Event time (ISO 8601 UTC) |
| `type` | enum | **R\*** | Event type — table below |
| `to_status_id` | integer | **C** | New status. **Required when `type` = `status_changed`.** |
| `to_severity_id` | integer | **C** | New severity. **Required when `type` = `severity_changed`.** |

**`type` values:**

| Value | When it is written | Additional field |
|---|---|---|
| `case_opened` | Case was opened | — |
| `case_closed` | Case was closed | — |
| `case_reopened` | A closed case was reopened | — |
| `status_changed` | Status changed | `to_status_id` |
| `comment_added` | A comment was written | — |
| `task_created` | A task was created | — |
| `task_completed` | A task was completed | — |
| `severity_changed` | Severity was reassessed | `to_severity_id` |
| `artifact_added` | A new IOC or piece of evidence was added | — |
| `other` | Does not match any of the above | — |

```json
"activity": [
  { "time": "2026-08-13T03:50:00Z", "type": "case_opened" },
  { "time": "2026-08-13T03:58:00Z", "type": "status_changed", "to_status_id": 2 },
  { "time": "2026-08-13T04:10:00Z", "type": "task_created" },
  { "time": "2026-08-13T04:22:00Z", "type": "comment_added" },
  { "time": "2026-08-13T04:35:00Z", "type": "task_completed" },
  { "time": "2026-08-13T06:20:00Z", "type": "severity_changed", "to_severity_id": 5 },
  { "time": "2026-08-15T11:00:00Z", "type": "case_closed" },
  { "time": "2026-08-16T09:30:00Z", "type": "case_reopened" }
]
```

> ## Comment text is NOT SENT
>
> `comment_added` indicates only the **fact and time that a comment was written** — not the text itself.

**The full history is sent.** At every update the entire chronology is resent, not just the new entries.

**Where it is taken from in the source systems:**

| System | Source |
|---|---|
| TheHive | `Case Logs`, `Task Logs`, audit trail |
| Cortex XSOAR | `War Room` entries, `Incident Audit Trail` |
| Microsoft Sentinel | `Comments` + status changes in the `SecurityIncident` table |
| Splunk SOAR | Container audit, `Notes` |
| IBM QRadar SOAR | Incident timeline |
| ServiceNow SIR | `Activity Stream`, `Work Notes` |
| Updive | Case activity stream |

> **`case_reopened` is of particular importance.** The reopening of a closed incident means the incident was not resolved properly. This is a quality signal visible at the national level, and `status_id` alone does not show it: it simply goes back from `5` to `2`, and without the history this cannot be detected.

## 2.5 Minimal example — with the fewest fields

If the organization does not have full information, the following payload is accepted:

```json
{
  "telemetry_type": "incident_batch",
  "schema_version": "1.0",
  "org_id": "b3f1c2a4-1d2e-4f56-9abc-1234567890ab",
  "collected_at": "2026-08-13T03:50:00Z",
  "incidents": [
    {
      "report_id": "99a3488d-1523-5499-85e7-afa2a6595466",
      "source_case_id": "CASE-2026-0442",
      "tlp": "AMBER",
      "lifecycle": {
        "status_id": 1,
        "detected_at": "2026-08-13T03:42:00Z",
        "opened_at": "2026-08-13T03:50:00Z",
        "updated_at": "2026-08-13T03:50:00Z",
        "closed_at": null
      },
      "classification": {
        "event_category": "intrusion_attempts",
        "event_type": "brute_force",
        "title": "SSH brute-force hujumi",
        "description": "Bitta tashqi manzildan takroriy autentifikatsiya urinishlari, keyin muvaffaqiyatli kirish.",
        "severity_id": 4
      },
      "technical": {
        "affected_asset_uids": [
          "web014"
        ],
        "indicators": [
          {
            "type": "ipv4",
            "value": "203.0.113.44"
          }
        ]
      }
    }
  ]
}
```

## 2.6 Closure example

```json
{
  "telemetry_type": "incident_batch",
  "schema_version": "1.0",
  "org_id": "b3f1c2a4-1d2e-4f56-9abc-1234567890ab",
  "collected_at": "2026-08-15T11:00:00Z",
  "incidents": [
    {
      "report_id": "8f339179-64ae-5763-99ab-2a0c6562203e",
      "source_case_id": "CASE-2026-0441",
      "tlp": "AMBER",
      "lifecycle": {
        "status_id": 5,
        "detected_at": "2026-08-13T03:42:00Z",
        "opened_at": "2026-08-13T03:50:00Z",
        "updated_at": "2026-08-15T11:00:00Z",
        "closed_at": "2026-08-15T11:00:00Z",
        "time_to_acknowledge_sec": 480,
        "time_to_contain_sec": 9000,
        "time_to_resolve_sec": 199080,
        "verdict_id": 2
      },
      "classification": {
        "event_category": "malicious_code",
        "event_type": "infected_system",
        "title": "Internetga ochiq serverda shifrlovchi zararli dastur",
        "description": "Hodisa hal qilindi. Serverlar tozalandi, yamoq o'rnatildi, kredensiallar almashtirildi.",
        "severity_id": 5
      },
      "technical": {
        "affected_asset_uids": [
          "web014",
          "web015"
        ],
        "indicators": [
          {
            "type": "ipv4",
            "value": "203.0.113.55"
          }
        ]
      },
      "response": {
        "actions_taken": [
          "patched CVE-2026-12345",
          "rebuilt affected servers"
        ],
        "containment_status": "recovered",
        "closing_note": "Serverlar qayta qurildi, yamoq o'rnatildi, xizmat normal ishga qaytdi."
      },
      "related_report_ids": [
        "99a3488d-1523-5499-85e7-afa2a6595466"
      ],
      "activity": [
        {
          "time": "2026-08-13T03:50:00Z",
          "type": "case_opened"
        },
        {
          "time": "2026-08-13T03:58:00Z",
          "type": "status_changed",
          "to_status_id": 2
        },
        {
          "time": "2026-08-14T16:30:00Z",
          "type": "status_changed",
          "to_status_id": 4
        },
        {
          "time": "2026-08-15T11:00:00Z",
          "type": "case_closed"
        }
      ]
    }
  ]
}
```

## 2.7 Common mistakes

| Mistake | Consequence | Correct solution |
|---|---|---|
| New `report_id` at every update | One incident appears as 5 in national statistics | Use the formula from §1.5 |
| `event_type` does not match the category | `422` error | Check against the Appendix A table |
| `org_id` inside the incident element | `422` error — it belongs to the envelope | Once in the envelope |
| Own `report_id` inside `related_report_ids` | `422` error | This field references only OTHER incidents |
| Several organizations in one request | `422` error | A separate request for each `org_id` |
| Source system status sent as-is (`"Active"`, `"Done"`) | `422` error | Convert to `status_id` via the Appendix B.5 mapping table |
| `contained` meaning assigned to `status_id` | Workflow and response phase get mixed up | Containment is expressed in `containment_status` |
| `detected_at` = `opened_at` | The detection-to-response interval appears as 0, the MTTA metric is broken | Take the tool's real detection time |
| `affected_asset_uids` empty even though assets are known | The incident is not linked to any asset, most of the correlation is lost | Filled in when the assets are known. If no internal asset was involved or the scope is not yet determined, `[]` is sent and filled in at the next lifecycle update. |
| Internal IPs included in `indicators` | False matches with other organizations, false "campaign" signal | Filter out RFC 1918 addresses |
| Raw log written into `description` | Leakage of confidential information | Write only a sanitized summary |
| Host name/IP written into `actions_taken` or `closing_note` | TLP:RED data leaks into an AMBER incident | Generic wording: "Infected host was isolated" |
| Comment text sent in `activity` | `422` error — no such field in the schema | Only `time` and `type` are sent |
| Only the latest new entries in `activity` | The chronology breaks | Full history at every update |
| `0` or `99` sent as `status_id` | `422` error | Only `1`–`5`; choose the closest match from Appendix B.5 |
| Local time (without `+05:00`) | All trend charts shift by 5 hours | Convert to UTC, append `Z` |

---

# 3. Alert — OCSF Detection Finding

## 3.1 Definition and difference from an incident

An alert is **a single detection produced by a single security tool**. It is expressed in the **Detection Finding** class of the OCSF 1.9.0 standard (`class_uid = 2004`, `category_uid = 2 Findings`).


**Important:** in an alert, `activity_id` is **always `1` (Create)**. An alert is an immutable detection fact. If its state changes (closed, found to be a false positive), this is expressed in the incident telemetry, not in the alert. Otherwise the connector would have to rescan the entire alert database on every cycle.

## 3.2 Submission format — envelope

The request body is an **envelope**: the organization identification is given once at the top, and the alerts are in the `alerts[]` array.

```json
{
  "telemetry_type": "alert_batch",
  "schema_version": "1.0",
  "org_id": "b3f1c2a4-1d2e-4f56-9abc-1234567890ab",
  "collected_at": "2026-08-13T04:15:00Z",
  "alerts": [ /* OCSF Detection Finding obyektlari */ ]
}
```

| Field | Type | R/O | Definition |
|---|---|---|---|
| `telemetry_type` | string | **R** | Fixed value: `"alert_batch"` |
| `schema_version` | string | **R** | `"1.0"` |
| `org_id` | UUID | **R** | The organization the alerts belong to — the **data owner** (§1.3). One organization per request. |
| `collected_at` | timestamp | **R** | Time the batch was collected by the integration. **ISO 8601 UTC.** |
| `alerts` | array | **R** | 1–500 OCSF Detection Finding objects |

- **One `org_id`** per request. An MSSP sends a separate request for each client.
- The envelope is used even when sending a single alert: `"alerts": [ { ... } ]`.
- Alert elements **do not contain `org_id` or `collected_at`** — these are in the envelope.

> Both `collected_at` (ISO 8601) and the `time` inside the alert (epoch ms) are present, and this is **not an error**: `time` is when the tool detected it, `collected_at` is when the integration received it. The difference shows the delivery delay.

## 3.3 Full JSON example — a single alert

Below is one element of the `alerts[]` array shown in full (the envelope is in §3.2):

```json
{
  "class_uid": 2004,
  "category_uid": 2,
  "activity_id": 1,
  "type_uid": 200401,

  "time": 1786594364512,
  "start_time": 1786594304512,
  "end_time": 1786594364512,

  "severity_id": 4,
  "status_id": 1,

  "count": 3,

  "metadata": {
    "version": "1.9.0",
    "product": {
      "name": "Wazuh",
      "version": "4.7.2"
    },
    "event_code": "5715",
    "logged_time": 1786594364900
  },

  "finding_info": {
    "uid": "wazuh-1691-abc",
    "title": "sshd: brute force trying to get access to the system",
    "attacks": [
      {
        "technique":     { "uid": "T1110" },
        "sub_technique": { "uid": "T1110.001" },
        "tactic":        { "uid": "TA0006" }
      }
    ]
  },

  "device": {
    "hostname": "web014",
    "ip": "10.0.2.14",
    "mac": "00:1a:2b:3c:4d:5e"
  },

  "observables": [
    { "type_id": 2,  "value": "203.0.113.44" },
    { "type_id": 1,  "value": "web014" },
    { "type_id": 11, "value": "22" },
    { "type_id": 18, "value": "CVE-2024-6387" }
  ],

  "vulnerabilities": [
    {
      "cve": { "uid": "CVE-2024-6387" },
      "severity": "High"
    }
  ]
}
```

## 3.4 Fields

### 3.4.1 OCSF classification — fixed (const) values

These four fields are **always the same**. If any other value is sent, the payload is rejected.

| Field | Type | R/O | Value | Why |
|---|---|---|---|---|
| `class_uid` | integer | **R · STD** | `2004` | OCSF Detection Finding class |
| `category_uid` | integer | **R · STD** | `2` | OCSF Findings category |
| `activity_id` | integer | **R · STD** | `1` | Create. An alert is immutable — no other value |
| `type_uid` | integer | **R · STD** | `200401` | `class_uid × 100 + activity_id` |

**Text names in OCSF — for reference, not sent:**

| Field | Value | OCSF text |
|---|---|---|
| `class_uid` | `2004` | Detection Finding |
| `category_uid` | `2` | Findings |
| `activity_id` | `1` | Create |
| `type_uid` | `200401` | Detection Finding: Create |

### 3.4.2 Time fields — all in epoch milliseconds

| Field | Type | R/O | Definition |
|---|---|---|---|
| `time` | integer | **R** | Time the detection fired, **epoch ms**. |
| `start_time` | integer | **O** | Time the observed activity started. |
| `end_time` | integer | **O** | Time the observed activity ended. |

> **`start_time` and `end_time` are a pair.** If `end_time` is sent, `start_time` is also required and `start_time ≤ end_time` must hold. Otherwise `422`. For aggregated detections (for example 500 attempts in 10 minutes) this window, together with `count`, shows the attack intensity.

### 3.4.3 Severity, status, aggregation

| Field | Type | R/O | Allowed values |
|---|---|---|---|
| `severity_id` | integer | **R · STD** | `0` Unknown · `1` Informational · `2` Low · `3` Medium · `4` High · `5` Critical · `99` Other |
| `status_id` | integer | **O · STD** | Triage status of the alert: `0` Unknown · `1` New · `2` In Progress · `3` Suppressed · `4` Resolved · `5` Archived · `99` Other. Mapping: **Appendix B.2**. |
| `count` | integer | **O** | Number of events the source aggregated into this single detection (for example Wazuh `rule.firedtimes`) |

> **`severity_id` is NOT a range.** Only `{0, 1, 2, 3, 4, 5, 99}` is accepted. `7`, `50`, `12` — invalid.
> **`severity_id = 0`** is used **honestly** when the source system did not provide a severity level. Do not invent one.

> **`status_id` and updating an alert.** When the alert status changes (for example it becomes `Suppressed`), it may be resent with the **same** `finding_info.uid` — the record is overwritten. Idempotency key: `org_id` + `metadata.product.name` + `finding_info.uid`. In stateless systems such as Wazuh this field is left empty.

**Mapping from source systems to `severity_id`:**

| Source value | `severity_id` |
|---|---|
| **Wazuh** `rule.level` 0–3 | `1` Informational |
| **Wazuh** `rule.level` 4–6 | `2` Low |
| **Wazuh** `rule.level` 7–9 | `3` Medium |
| **Wazuh** `rule.level` 10–12 | `4` High |
| **Wazuh** `rule.level` 13–15 | `5` Critical |
| **Sentinel / Defender** Informational | `1` |
| **Sentinel / Defender** Low | `2` |
| **Sentinel / Defender** Medium | `3` |
| **Sentinel / Defender** High | `4` |
| **Splunk ES** urgency: informational | `1` |
| **Splunk ES** urgency: low | `2` |
| **Splunk ES** urgency: medium | `3` |
| **Splunk ES** urgency: high | `4` |
| **Splunk ES** urgency: critical | `5` |
| **Elastic** severity: low / medium / high / critical | `2` / `3` / `4` / `5` |
| **QRadar** magnitude 1–2 | `1` |
| **QRadar** magnitude 3–4 | `2` |
| **QRadar** magnitude 5–6 | `3` |
| **QRadar** magnitude 7–8 | `4` |
| **QRadar** magnitude 9–10 | `5` |
| **Suricata / Snort** priority `4` | `2` |
| **Suricata / Snort** priority `3` | `3` |
| **Suricata / Snort** priority `2` | `4` |
| **Suricata / Snort** priority `1` | `5` |

> **In Suricata and Snort the order is reversed:** `1` is the highest severity, `4` the lowest. If copied directly, critical alerts end up as `Low`.

**For systems that provide only a numeric score (0–100 scale):**

| Range | `severity_id` |
|---|---|
| 0–19 | `1` Informational |
| 20–39 | `2` Low |
| 40–59 | `3` Medium |
| 60–79 | `4` High |
| 80–100 | `5` Critical |

### 3.4.4 `metadata` — about the source system

| Field | Type | R/O | Definition |
|---|---|---|---|
| `metadata.version` | string | **R · STD** | Fixed: `"1.9.0"` — OCSF schema version |
| `metadata.product.name` | string | **R** | Tool name: `"Wazuh"`, `"CrowdStrike Falcon"`, `"Microsoft Defender"` |
| `metadata.product.version` | string | **O** | Tool version |
| `metadata.event_code` | string | **O** | ID of the rule/signature that fired (Wazuh `rule.id`, Sigma rule id) |
| `metadata.logged_time` | integer | **O** | Time the log entered the system (epoch ms) |


### 3.4.5 `finding_info` — the detection itself

| Field | Type | R/O | Definition |
|---|---|---|---|
| `finding_info.uid` | string | **R** | **The source tool's own ID for this detection.** Must be stable — it is the idempotency key and the link point to `alerts[]` in the incident. |
| `finding_info.title` | string | **R** | **Rule name**, ≤300 characters. NOT the event text: `"SSH brute-force detected"` — correct, `"Failed login for user admin from 10.0.2.14"` — incorrect (the values belong in `observables`). |
| `finding_info.attacks[]` | array | **O · STD** | MITRE ATT&CK. Each element must contain **at least one** of `technique`, `sub_technique` or `tactic`. |

**`attacks[]` element:**

```json
{
  "technique":     { "uid": "T1110" },
  "sub_technique": { "uid": "T1110.001" },
  "tactic":        { "uid": "TA0006" }
}
```

`uid` values are taken **from the MITRE catalog**: technique `T####`, sub-technique `T####.###`, tactic `TA####`. The name is not written — only the ID.

**If the source system provides only a name** (for example Wazuh `rule.mitre.tactic` = `"Credential Access"`), the developer looks up the ID from the name and sends it: the full list of tactics is in **Appendix B.9**, techniques are at `https://attack.mitre.org/`.

### 3.4.6 `device` — affected device

| Field | Type | R/O | Definition |
|---|---|---|---|
| `device.hostname` | string | **R** | **Linking key to the asset inventory.** In normalized form it must equal `assets[].asset_uid` (rule: §2.4.7). |
| `device.ip` | string | **O** | IP address |
| `device.mac` | string | **O** | MAC address, **in lowercase**: `00:1a:2b:3c:4d:5e`. Compared against `technical.mac_addresses[]` in the asset. |

### 3.4.7 `observables` — indicators

| Field | Type | R/O | Definition |
|---|---|---|---|
| `observables[].type_id` | integer | **R\* · STD** | See the table below |
| `observables[].value` | string | **R\*** | Value. External values are refanged; domains and hashes are written in lowercase. |

> **Internal values are also sent.** Unlike `indicators[]` (incident), `observables[]` receives **all** values encountered in the alert — including the victim hostname and internal IP. Reason: they are needed to link to the asset, i.e. to build the list of "alerts on this asset". For cross-organization campaign hunting, UzCORE takes only external values into account.

**Allowed `type_id` values:**

| ID | Name | Example |
|---|---|---|
| `0` | Unknown | — |
| `1` | Hostname | `web014` |
| `2` | IP Address | `203.0.113.44` |
| `3` | MAC Address | `00:1A:2B:3C:4D:5E` |
| `4` | User Name | `svc_backup` |
| `5` | Email Address | `sender@example.com` |
| `6` | URL String | `http://evil.example/payload` |
| `7` | File Name | `invoice.pdf.exe` |
| `8` | Hash | `9f86d081884c...` |
| `10` | Resource UID | — |
| `11` | Port | `22` |
| `18` | CVE uid | `CVE-2024-6387` |
| `99` | Other | — |


### 3.4.8 `vulnerabilities` — vulnerabilities

| Field | Type | R/O | Definition |
|---|---|---|---|
| `vulnerabilities[].cve.uid` | string | **R\* · STD** | CVE identifier, in the format `CVE-YYYY-NNNN+` |
| `vulnerabilities[].severity` | string | **O** | Vulnerability severity as reported by the source system: `"Critical"`, `"High"`, `"Medium"`, `"Low"` |

## 3.5 Minimal alert example

```json
{
  "telemetry_type": "alert_batch",
  "schema_version": "1.0",
  "org_id": "b3f1c2a4-1d2e-4f56-9abc-1234567890ab",
  "collected_at": "2026-08-13T04:15:00Z",
  "alerts": [
    {
      "class_uid": 2004,
      "category_uid": 2,
      "activity_id": 1,
      "type_uid": 200401,
      "time": 1786594364512,
      "severity_id": 4,
      "metadata": {
        "version": "1.9.0",
        "product": { "name": "Wazuh" }
      },
      "finding_info": {
        "uid": "wazuh-1691-abc",
        "title": "sshd: brute force trying to get access to the system"
      },
      "device": { "hostname": "web014" }
    }
  ]
}
```


## 3.6 Common mistakes

| Mistake | Consequence | Correct solution |
|---|---|---|
| `os.type_id: 201` for Linux | The entire Linux fleet appears as Android | Linux = `200` |
| `time` sent in seconds | The date falls back to 1970 | Milliseconds: `× 1000` |
| `severity_id: 12` | `422` error | Only `{0,1,2,3,4,5,99}` |
| `org_id` inside an alert element | `422` error — it belongs in the envelope | Once in the envelope |
| Request body is an array (`[...]`) | `400` error | Envelope object: `{ "alerts": [...] }` |

---

# 4. Asset Inventory — asset inventory

## 4.1 Definition and confidentiality

The list of an organization's assets. Assets are divided into two groups:

| Group | Classes | Typical source |
|---|---|---|
| **Technical assets** | `hardware`, `software`, `network`, `service`, `information_resource`, `security_tool` | SIEM / EDR / vulnerability scanner — automatic |
| **Register assets** | `information`, `process`, `personnel`, `site`, `organization`, `intangible` | Entered manually by the organization or from a CMDB/GRC system (the information asset register maintained under Annex L of O'zMSt 816:2025) |

The taxonomy — 12 classes and 70 types — is based on **O'zMSt 816:2025** (§7.9.2 protected objects) and extended with O'zMSt ISO/IEC 27005:2024, ISO/IEC 27001:2022 Annex A and ПҚ-167 (full list: **Appendix E**). The organization decides which classes to submit: whatever is submitted is accepted.

> ## ⚠️ CONFIDENTIALITY — TLP:RED
>
> This telemetry contains **hostnames, IP addresses, open ports and vulnerabilities**.
>
> **Mandatory measures on the organization's side:** submit only over TLS 1.2+, only `RED` in the `tlp` field.
>
> In the `personnel` class, **names, logins, emails and phone numbers are never written anywhere**, including in `asset_uid`. `asset_uid` is anonymous: `role-ciso`, `user-0417`.

## 4.2 Submission mode — upsert

UzCORE accepts assets on an **upsert** basis: an incoming asset is written to the database or the existing record is updated. An asset that is not submitted is **not deleted** — it stays in the database, only its `last_seen` value is not refreshed.

For this reason, technical and register assets can be submitted **separately, at different cadences**: the SIEM submits technical assets daily, while the manually maintained register is submitted when it changes. They do not interfere with each other.

| Rule | Details |
|---|---|
| **Interval** | Technical assets — once a day (recommended: at night). Register assets — when they change. |
| **Deleting an asset** | Only with an explicit signal: `lifecycle_status: "decommissioned"` is submitted. Absence from the list means nothing. |
| **Stale asset** | An asset whose `last_seen` has not been refreshed for a long time is marked as "stale" — **only for `provenance: "discovered"`** assets. Manually entered (`declared`) assets are submitted rarely, so this rule does not apply to them. |
| **Idempotency** | Thanks to upsert, resubmitting the same snapshot does not create duplicate records — an asset is identified by `org_id` + `asset_uid`. |

## 4.3 Full JSON example

One technical asset (from the SIEM) and one register asset (entered manually):

```json
{
  "telemetry_type": "asset_inventory",
  "schema_version": "1.0",
  "org_id": "b3f1c2a4-1d2e-4f56-9abc-1234567890ab",
  "tlp": "RED",
  "source_system": "Wazuh",
  "collected_at": "2026-08-13T02:00:00Z",
  "summary": {
    "total_assets": 1284,
    "servers": 210,
    "endpoints": 940,
    "network_devices": 86,
    "ot_ics_devices": 12,
    "internet_facing": 34,
    "end_of_life": 23
  },
  "assets": [
    {
      "asset_uid": "web014",
      "asset_class": "hardware",
      "asset_type": "server",
      "criticality": "crown_jewel",
      "lifecycle_status": "active",
      "provenance": "discovered",
      "first_seen": "2024-03-11T09:00:00Z",
      "last_seen": "2026-08-13T01:58:00Z",
      "related_asset_uids": [
        "db02"
      ],
      "technical": {
        "hostname": "web014.bank.local",
        "manufacturer": "Dell",
        "model": "PowerEdge R750",
        "os": {
          "type_id": 200,
          "name": "Ubuntu Server",
          "version": "22.04",
          "build": "5.15.0-101"
        },
        "ip_addresses": [
          {
            "value": "10.0.2.14",
            "type": "ipv4",
            "scope": "internal"
          },
          {
            "value": "203.0.113.14",
            "type": "ipv4",
            "scope": "public"
          }
        ],
        "mac_addresses": [
          "00:1a:2b:3c:4d:5e"
        ],
        "open_ports": [
          22,
          80,
          443
        ],
        "exposure": "internet_facing",
        "environment": "production",
        "software_inventory": [
          {
            "product": "Apache HTTP Server",
            "version": "2.4.58",
            "cpe": "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"
          },
          {
            "product": "OpenSSH",
            "version": "9.6p1",
            "cpe": "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"
          }
        ],
        "known_cves": [
          {
            "cve_id": "CVE-2026-12345",
            "status": "unpatched",
            "detected_at": "2026-08-01T04:00:00Z"
          }
        ]
      }
    },
    {
      "asset_uid": "role-ciso",
      "asset_class": "personnel",
      "asset_type": "responsible_person",
      "criticality": "high",
      "lifecycle_status": "active",
      "provenance": "declared",
      "related_asset_uids": [
        "web014",
        "db02"
      ],
      "personnel": {
        "represents": "role",
        "headcount": 1,
        "role_category": "ciso",
        "employment_type": "employee",
        "privileged_access": true,
        "privileged_scope": [
          "security_tools"
        ],
        "segregation_of_duties_conflict": false,
        "screening_completed": true,
        "nda_signed": true,
        "security_training": {
          "completed": true,
          "last_completed_at": "2026-04-20"
        },
        "remote_access": true,
        "access_to_confidentiality_marks": ["KO", "PD", "DSP"]
      }
    }
  ]
}
```

## 4.4 Fields

### 4.4.1 Envelope

| Field | Type | R/O | Definition and allowed values |
|---|---|---|---|
| `telemetry_type` | string | **R** | Fixed: `"asset_inventory"` |
| `schema_version` | string | **R** | `"1.0"` |
| `org_id` | UUID | **R** | The organization the assets belong to — the data owner (§1.3) |
| `tlp` | enum | **R** | Always `"RED"`. Any other value is rejected. |
| `source_system` | string | **O** | The tool that provided the data: `"Wazuh"`, `"Splunk"`, `"Tenable"`, `"CMDB"` |
| `collected_at` | timestamp | **R** | Time the data was collected (ISO 8601 UTC) |
| `summary` | object | **R** | Quick indicators (§4.4.2) |
| `assets` | array | **R** | List of assets |

### 4.4.2 `summary` — quick indicators

These blocks are shown on the dashboard immediately and are computed without reading the whole `assets[]` array.

| Field | Type | R/O | Definition |
|---|---|---|---|
| `summary.total_assets` | integer | **R** | Total number of devices. **The denominator for all normalized indicators** — for example "incidents per 100 assets". |
| `summary.servers` | integer | **O** | Number of servers |
| `summary.endpoints` | integer | **O** | Number of workstations and laptops |
| `summary.network_devices` | integer | **O** | Number of routers, switches, firewalls |
| `summary.ot_ics_devices` | integer | **O** | Operational technology / industrial control devices |
| `summary.internet_facing` | integer | **O** | Assets visible from the internet — **the key figure of the national attack surface** |
| `summary.end_of_life` | integer | **O** | Unsupported software/hardware |

### 4.4.3 `assets[]` — structure

Each asset consists of two parts: a **common core** (identical for all classes) and **one object matching the class**.

```
aktiv
 ├── umumiy yadro         asset_uid, asset_class, asset_type, criticality, ...
 └── klass obyekti        technical    ← hardware / software / network / service /
                                         information_resource / security_tool
                          information  ← information
                          process      ← process
                          personnel    ← personnel
                          site         ← site
                          organization ← organization
                          intangible   ← intangible
```

**Rule:** each asset may contain **only the object matching its own class**. For example, if a `personnel` asset contains a `technical` object, the payload is rejected — an employee has no IP address or open ports.

### 4.4.4 Common core — for all classes

| Field | Type | R/O | Definition and allowed values |
|---|---|---|---|
| `asset_uid` | string | **R\*** | **Stable unique ID — the primary linking key.** Must be written identically to the incident `affected_asset_uids` and the alert `device.hostname`. Does not change between snapshots. |
| `asset_class` | enum | **R\* · STD** | One of 12 classes: `information` │ `process` │ `hardware` │ `software` │ `network` │ `service` │ `information_resource` │ `security_tool` │ `personnel` │ `site` │ `organization` │ `intangible` |
| `asset_type` | enum | **R\* · STD** | One of 70 types. **Must match the selected class.** Full list: **Appendix E** |
| `criticality` | enum | **O** | `crown_jewel` │ `high` │ `medium` │ `low` |
| `lifecycle_status` | enum | **O** | `active` │ `decommissioned` │ `end_of_life`. The only way to delete an asset is `decommissioned` (§4.2). |
| `provenance` | enum | **O** | `discovered` — found by a tool (evidence) │ `declared` — entered manually (claim) |
| `first_seen` | timestamp | **O** | Time first observed. Shows growth of unmanaged (shadow IT) assets. |
| `last_seen` | timestamp | **O** | Time last observed. The staleness rule applies only to `discovered` assets. |
| `related_asset_uids` | array[string] | **O** | The `asset_uid`s of related assets. See the examples below. |

> **In the `personnel` class, `asset_uid` is anonymous.** Names, logins, emails and phone numbers are not written: `role-ciso`, `role-soc-lead`, `user-0417`. Contacts for reaching people during an incident belong to the organization's registration data, not to telemetry.

**`related_asset_uids` — links between assets:**

| Asset | `related_asset_uids` | Meaning |
|---|---|---|
| `information_resource/web_resource` | `["web014"]` | The web resource runs on this server |
| `information/processed_data` | `["db02"]` | The data is stored in this database |
| `process/business_process` | `["app-payments", "db02"]` | The process depends on this application and database |
| `personnel/responsible_person` | `["web014", "db02"]` | The responsible person is accountable for these assets |
| `organization/supplier` | `["fw01"]` | The supplier services this device |

The national value of register assets lies precisely in these links: for example, "which servers does the payment process depend on" or "which systems does this supplier have access to".

### 4.4.5 `technical` — technical classes

`hardware`, `software`, `network`, `service`, `information_resource`, `security_tool` — a **required** object for these six classes. Prohibited in other classes.

| Field | Type | R/O | Definition and allowed values |
|---|---|---|---|
| `hostname` | string | **O** | Full hostname / FQDN (`web014.bank.local`) |
| `manufacturer` | string | **O** | Hardware manufacturer: `"Dell"`, `"HP"`, `"Cisco"`. For responding to supply-chain vulnerabilities. |
| `model` | string | **O** | Model: `"PowerEdge R750"` |
| `os.type_id` | integer | **O · STD** | OCSF enum, same as in alerts: `0` Unknown · `100` Windows · `101` Windows Mobile · `200` Linux · `201` Android · `300` macOS · `301` iOS · `302` iPadOS · `400` Solaris · `401` AIX · `402` HP-UX · `99` Other (Appendix B.4) |
| `os.name` | string | **O** | `"Ubuntu Server"`, `"Windows Server"` |
| `os.version` | string | **O** | `"22.04"`, `"2022"` |
| `os.build` | string | **O** | Build / patch level: `"5.15.0-101"`, `"20348.2402"` |
| `ip_addresses[].value` | string | **R\*** | IP address |
| `ip_addresses[].type` | enum | **O** | `ipv4` │ `ipv6` |
| `ip_addresses[].scope` | enum | **R\*** | `internal` │ `public` │ `dmz` |
| `mac_addresses` | array[string] | **O** | MAC addresses, lowercase, colon-separated format: `["00:1a:2b:3c:4d:5e"]`. For matching against `device.mac` in alerts — a fallback linking path when `hostname` does not match. |
| `open_ports` | array[integer] | **O** | Open ports: `[22, 80, 443]`, 0–65535 |
| `as_protection_class` | enum | **O · STD** | Protection class of the automated system against unauthorized access (**O'z DSt 2814:2014**; O'zMSt 816:2025 §7.9.4): `3B` │ `3A` │ `2B` │ `2A` │ `1D` │ `1G` │ `1V` │ `1B` │ `1A`. **Only for the `information_system` and `industrial_control_system` types** — rejected for other types |
| `exposure` | enum | **R\*** | `internet_facing` │ `dmz` │ `internal`. **The most important filter** — the "critical vulnerabilities on internet-exposed assets" view relies on it. |
| `environment` | enum | **O** | `production` │ `staging` │ `development` │ `test` |
| `software_inventory[].product` | string | **R\*** | Product name: `"Apache HTTP Server"` |
| `software_inventory[].version` | string | **O** | Installed version. Without a version, CVE matching does not work. |
| `software_inventory[].cpe` | string | **O · STD** | CPE 2.3: `cpe:2.3:<part>:<vendor>:<product>:<version>:...` — 13 components, empty ones are `*`. Source: `https://nvd.nist.gov/products/cpe` |
| `known_cves[].cve_id` | string | **R\* · STD** | `CVE-YYYY-NNNN+`, uppercase. **The linking key for national early warning.** |
| `known_cves[].status` | enum | **O** | `unpatched` │ `patched` │ `mitigated` │ `accepted_risk` |
| `known_cves[].detected_at` | timestamp | **O** | Time the vulnerability was detected |

> **Difference between `exposure` and `ip_addresses[].scope`.** An asset may have an internal IP (`scope: internal`) yet be exposed to the internet via NAT or a reverse proxy (`exposure: internet_facing`). That is why both are needed.

> **Why `software_inventory` is needed when `known_cves` exists.** When a new critical CVE is published, the organizations' scanners have not yet been updated. UzCORE, however, immediately identifies who may be affected using the new CVE data and the software list. `cpe` makes this matching precise.

### 4.4.6 Register class objects

Separate objects for the `information`, `process`, `personnel`, `site`, `organization`, `intangible` classes. The fields are defined on the basis of **ISO/IEC 27002:2022** controls and **ISO/IEC 27005:2022** risk assessment principles.

All fields are **optional**. An empty object (`{}`) is also considered valid — the organization decides which fields to fill in.

---

#### `information` — information assets

Basis: **O'zMSt 816:2025 Annex L** (access restriction, integrity and availability categories); ISO 27002 **5.33** (protection of records), **5.34** (PII), **8.10** (deletion), **8.11** (masking), **8.12** (DLP), **8.13** (backup), **8.24** (cryptography).

| Field | Type | R/O | Definition and allowed values |
|---|---|---|---|
| `confidentiality_marks` | array[enum] | **O · STD** | Access restriction categories — see the table below. **Several may be combined**: `["PD","BT"]`. `OD` only on its own |
| `integrity_category` | enum | **O · STD** | `V` │ `N` │ `-` — see the table below |
| `availability_category` | enum | **O · STD** | `B` │ `V` │ `S` │ `N` — see the table below |
| `data_categories` | array[enum] | **O** | `financial` │ `health` │ `biometric` │ `commercial_secret` │ `operational` │ `technical` │ `telemetry` │ `other` |
| `contains_pii` | boolean | **O** | Whether personal data is present (27002 5.34) |
| `pii_volume_band` | enum | **O** | `none` │ `under_1k` │ `under_100k` │ `under_1m` │ `over_1m`. **No exact number is written.** If `contains_pii: false`, only `none` |
| `storage_location` | enum | **O** | `on_premise` │ `national_cloud` │ `foreign_cloud` │ `hybrid` │ `offline` — data residency (27002 5.23) |
| `retention_days` | integer | **O** | Retention period, in days. `0` — no period defined (27002 5.33, 8.10) |
| `encryption.at_rest` | boolean | **O** | Whether encrypted at rest (27002 8.24) |
| `encryption.in_transit` | boolean | **O** | Whether encrypted in transit |
| `masking_applied` | boolean | **O** | Whether masking / pseudonymization is applied (27002 8.11) |
| `dlp_applied` | boolean | **O** | Whether covered by a DLP tool (27002 8.12) |
| `backup.exists` | boolean | **O** | Whether a backup exists (27002 8.13) |
| `backup.frequency` | enum | **O** | `continuous` │ `hourly` │ `daily` │ `weekly` │ `monthly` │ `none` |
| `backup.offsite` | boolean | **O** | Whether the backup is stored at a different physical location |
| `backup.last_tested_at` | date | **O** | `YYYY-MM-DD`. Date the restore was last tested |
| `regulatory_scope` | array[enum] | **O** | `pq_167` │ `personal_data_law` │ `state_secret` │ `banking` │ `healthcare` │ `pci_dss` │ `gdpr` │ `other` (27002 5.31, 5.34) |

**Categories under Annex L of O'zMSt 816:2025:**

| Field | Code | Meaning |
|---|---|---|
| `confidentiality_marks` | `SS` | State secret — top secret |
| | `S` | State secret — secret |
| | `DSP` | For official use only |
| | `KT` | Commercial secret |
| | `BT` | Banking secret |
| | `PD` | Personal data |
| | `KO` | Confidential information of the organization |
| | `OD` | Public data |
| `integrity_category` | `V` | High — unauthorized modification causes significant direct damage |
| | `N` | Low — minor, uncertain damage |
| | `-` | Integrity assurance is not required |
| `availability_category` | `B` | Uninterrupted — outage does not exceed **1 minute** |
| | `V` | High — outage does not exceed **1 hour** |
| | `S` | Medium — outage does not exceed **12 hours** |
| | `N` | Low — outage may exceed 12 hours |

**Type and category consistency** — checked by the schema:

| `asset_type` | Must be present in `confidentiality_marks` |
|---|---|
| `state_secret` | `SS` or `S` |
| `confidential_data` | At least one of `DSP`, `KT`, `BT`, `PD` or `KO` |
| `personal_data` | `PD` |
| `public_data` | Only `["OD"]` |

The `PD` mark and `contains_pii` must not contradict each other: if `PD` is present, `contains_pii: false` is rejected; if `contains_pii: true`, `PD` must be present.

---

#### `process` — business processes

Basis: ISO 27002 **5.29** (security during disruption), **5.30** (ICT continuity, BIA), **5.2** (roles); ISO 27005 **7.3.2**.

| Field | Type | R/O | Definition and allowed values |
|---|---|---|---|
| `process_owner_uid` | string | **O** | The `asset_uid` of the process owner — an **anonymous** ID in the `personnel` class. No name is written (27002 5.2) |
| `citizen_facing` | boolean | **O** | Whether a disruption directly affects citizens. **The field that determines national priority** |
| `availability_category` | enum | **O · STD** | `B` │ `V` │ `S` │ `N` — Annex L of O'zMSt 816:2025, the same scale as in `information` |
| `bia.completed` | boolean | **O** | Whether a business impact analysis has been performed (27002 5.30) |
| `bia.last_review_at` | date | **O** | `YYYY-MM-DD` |
| `bia.rto_minutes` | integer | **O** | **RTO** — recovery time objective, in minutes |
| `bia.rpo_minutes` | integer | **O** | **RPO** — window of data that may be lost, in minutes |
| `bia.mtpd_minutes` | integer | **O** | **MTPD** — maximum tolerable period of disruption |
| `continuity_plan.exists` | boolean | **O** | Whether a continuity plan exists (27002 5.29, 5.30) |
| `continuity_plan.last_tested_at` | date | **O** | Date the plan was last tested |
| `continuity_plan.manual_fallback` | boolean | **O** | Whether manual execution is possible when IT is unavailable |
| `impact_if_disrupted` | enum | **O** | `low` │ `medium` │ `high` │ `critical` |
| `regulatory_scope` | array[enum] | **O** | Same list as in `information` |

---

#### `personnel` — employees and roles

Basis: ISO 27002 **5.2** (roles), **5.3** (segregation of duties), **6.1** (screening), **6.2** (contract), **6.3** (training), **6.6** (NDA), **6.7** (remote working), **8.2** (privileged access).

> ## ⚠️ PERSONAL DATA PROHIBITED
>
> This object contains **no first name, last name, login, email, phone number, date of birth, or free-text job title**. The schema does not accept them — `additionalProperties: false`.
>
> **Recommendation:** use `represents: "role"` or `"group"`. Representing a role instead of a single individual strengthens anonymity and keeps the list stable.

| Field | Type | R/O | Definition and allowed values |
|---|---|---|---|
| `represents` | enum | **O** | `individual` │ `role` │ `group` — who the record represents |
| `headcount` | integer | **O** | Number of people in this role/group. **Prohibited when `represents: "individual"`** |
| `role_category` | enum | **O** | `executive` │ `ciso` │ `security_officer` │ `soc_analyst` │ `system_admin` │ `network_admin` │ `dba` │ `developer` │ `ot_engineer` │ `help_desk` │ `auditor` │ `general_user` │ `other` (27002 5.2) |
| `employment_type` | enum | **O** | `employee` │ `contractor` │ `third_party` │ `intern` (27002 6.2, 5.19) |
| `privileged_access` | boolean | **O** | Whether privileged access is held (27002 8.2) |
| `privileged_scope` | array[enum] | **O** | `domain_admin` │ `server_admin` │ `database` │ `network` │ `ot_ics` │ `cloud` │ `security_tools` │ `backup` │ `source_code`. **Only when `privileged_access: true`** |
| `segregation_of_duties_conflict` | boolean | **O** | Whether segregation of duties is violated (27002 5.3) |
| `screening_completed` | boolean | **O** | Whether pre-employment screening was performed (27002 6.1) |
| `nda_signed` | boolean | **O** | Whether a non-disclosure agreement is signed (27002 6.6) |
| `security_training.completed` | boolean | **O** | Whether the awareness course is completed (27002 6.3) |
| `security_training.last_completed_at` | date | **O** | `YYYY-MM-DD` |
| `remote_access` | boolean | **O** | Whether remote working access is granted (27002 6.7) |
| `access_to_confidentiality_marks` | array[enum] | **O · STD** | Information categories the person has access to — codes from `information.confidentiality_marks`: `["KO","PD"]` |

---

#### `site` — physical facilities

Basis: ISO 27002 **7.1** (perimeter), **7.2** (entry control), **7.3** (securing rooms), **7.4** (physical monitoring), **7.5** (natural threats), **7.11** (supporting utilities).

> **NO EXACT ADDRESS IS RECORDED.** Street, building number and GPS coordinates are not in the schema. Only the **region code** — ISO 3166-2:UZ.

| Field | Type | R/O | Description and allowed values |
|---|---|---|---|
| `site_type` | enum | **O** | `datacenter` │ `colocation` │ `server_room` │ `office` │ `branch` │ `industrial_plant` │ `substation` │ `dr_site` │ `warehouse` │ `remote_facility` |
| `region_code` | enum | **O · STD** | ISO 3166-2:UZ — `UZ-AN` Andijan · `UZ-BU` Bukhara · `UZ-FA` Fergana · `UZ-JI` Jizzakh · `UZ-NG` Namangan · `UZ-NW` Navoi · `UZ-QA` Kashkadarya · `UZ-QR` Karakalpakstan · `UZ-SA` Samarkand · `UZ-SI` Syrdarya · `UZ-SU` Surkhandarya · `UZ-TK` Tashkent city · `UZ-TO` Tashkent region · `UZ-XO` Khorezm · `FOREIGN` — outside the country |
| `ownership` | enum | **O** | `owned` │ `leased` │ `colocation` │ `third_party` (27002 5.19) |
| `secure_area` | boolean | **O** | Whether it is designated as a secure area (27002 7.1, 7.3, 7.6) |
| `physical_access_control` | array[enum] | **O** | `none` │ `key` │ `badge` │ `pin` │ `biometric` │ `mantrap` │ `guard` │ `visitor_log` (27002 7.2) |
| `physical_monitoring` | array[enum] | **O** | `none` │ `cctv` │ `intruder_alarm` │ `guard_patrol` │ `access_log` │ `environmental_sensor` (27002 7.4) |
| `supporting_utilities` | array[enum] | **O** | `ups` │ `generator` │ `redundant_power` │ `cooling` │ `fire_suppression` │ `water_detection` │ `redundant_telecom` (27002 7.11) |
| `environmental_threats` | array[enum] | **O** | `none` │ `seismic` │ `flood` │ `fire` │ `extreme_heat` │ `dust` │ `power_instability` (27002 7.5) |
| `hosts_critical_assets` | boolean | **O** | Whether `crown_jewel` or `high` assets are located at this facility |

---

#### `organization` — external organizations and units

Basis: ISO 27002 **5.19** (supplier relationships), **5.20** (security in supplier agreements), **5.21** (ICT supply chain), **5.22** (monitoring and review of services), **5.23** (cloud services); ISO 27005 **7.2**.

| Field | Type | R/O | Description and allowed values |
|---|---|---|---|
| `org_role` | enum | **O** | `supplier` │ `ict_supplier` │ `cloud_provider` │ `mssp` │ `subcontractor` │ `internal_unit` │ `partner` │ `regulator` |
| `org_ref` | string | **O** | Registration code of the **legal entity** (TIN). The code of a natural person or sole proprietor is **not recorded** |
| `country_code` | string | **O · STD** | ISO 3166-1 alpha-2, upper case: `UZ`, `RU`, `CN`, `US` (27002 5.21) |
| `access_type` | array[enum] | **O** | `none` │ `physical` │ `remote_logical` │ `privileged` │ `data_processing` │ `source_code` │ `onsite_staff` │ `managed_security` (27002 5.19, 5.20) |
| `agreement.nda` | boolean | **O** | Whether a non-disclosure agreement exists |
| `agreement.security_clauses` | boolean | **O** | Whether the contract contains security clauses (27002 5.20) |
| `agreement.sla` | boolean | **O** | Whether an SLA exists |
| `agreement.right_to_audit` | boolean | **O** | Whether there is a right to audit |
| `agreement.incident_notification` | boolean | **O** | Whether there is an obligation to notify of incidents |
| `security_certification` | array[enum] | **O** | `none` │ `iso_27001` │ `iso_22301` │ `pci_dss` │ `soc2` │ `national_cert` │ `other` (27002 5.21, 5.22) |
| `last_review_at` | date | **O** | Date of the last security review (27002 5.22) |
| `concentration_risk` | boolean | **O** | Whether there is a dependency on this supplier with no alternative (27005 7.2) |

---

#### `intangible` — intangible assets

Basis: O'zMSt 816:2025 §7.9.2 f); O'zMSt ISO/IEC 27005:2024 A.2.2 — primary asset.

Its fields are not yet defined — for now only an empty object (`{}`) is accepted. An intangible asset has no IP address or vulnerability; its significance lies in its links to other assets — via `related_asset_uids`.

---

#### Example — five registry assets

```json
{
  "assets": [
    {
      "asset_uid": "data-cards",
      "asset_class": "information",
      "asset_type": "processed_data",
      "criticality": "crown_jewel",
      "provenance": "declared",
      "related_asset_uids": ["db02"],
      "information": {
        "confidentiality_marks": ["PD", "BT"],
        "integrity_category": "V",
        "availability_category": "V",
        "data_categories": ["financial"],
        "contains_pii": true,
        "pii_volume_band": "under_1m",
        "storage_location": "on_premise",
        "retention_days": 1825,
        "encryption": { "at_rest": true, "in_transit": true },
        "masking_applied": true,
        "dlp_applied": true,
        "backup": {
          "exists": true,
          "frequency": "daily",
          "offsite": true,
          "last_tested_at": "2026-08-01"
        },
        "regulatory_scope": ["pq_167", "personal_data_law", "pci_dss"]
      }
    },
    {
      "asset_uid": "proc-payments",
      "asset_class": "process",
      "asset_type": "business_process",
      "criticality": "crown_jewel",
      "related_asset_uids": ["app-payments", "db02"],
      "process": {
        "process_owner_uid": "role-ciso",
        "citizen_facing": true,
        "availability_category": "B",
        "bia": {
          "completed": true,
          "last_review_at": "2026-03-15",
          "rto_minutes": 60,
          "rpo_minutes": 15,
          "mtpd_minutes": 240
        },
        "continuity_plan": {
          "exists": true,
          "last_tested_at": "2026-06-01",
          "manual_fallback": false
        },
        "impact_if_disrupted": "critical",
        "regulatory_scope": ["banking"]
      }
    },
    {
      "asset_uid": "role-dba",
      "asset_class": "personnel",
      "asset_type": "user",
      "criticality": "high",
      "related_asset_uids": ["db02"],
      "personnel": {
        "represents": "group",
        "headcount": 4,
        "role_category": "dba",
        "employment_type": "employee",
        "privileged_access": true,
        "privileged_scope": ["database", "backup"],
        "segregation_of_duties_conflict": false,
        "screening_completed": true,
        "nda_signed": true,
        "security_training": {
          "completed": true,
          "last_completed_at": "2026-02-10"
        },
        "remote_access": false,
        "access_to_confidentiality_marks": ["KO", "PD"]
      }
    },
    {
      "asset_uid": "dc-main",
      "asset_class": "site",
      "asset_type": "datacenter",
      "criticality": "crown_jewel",
      "related_asset_uids": ["web014", "db02"],
      "site": {
        "site_type": "datacenter",
        "region_code": "UZ-TK",
        "ownership": "owned",
        "secure_area": true,
        "physical_access_control": ["badge", "biometric", "mantrap", "visitor_log"],
        "physical_monitoring": ["cctv", "intruder_alarm", "access_log"],
        "supporting_utilities": ["ups", "generator", "cooling", "fire_suppression"],
        "environmental_threats": ["seismic", "power_instability"],
        "hosts_critical_assets": true
      }
    },
    {
      "asset_uid": "sup-netvendor",
      "asset_class": "organization",
      "asset_type": "supplier",
      "criticality": "high",
      "related_asset_uids": ["fw01"],
      "organization": {
        "org_role": "ict_supplier",
        "org_ref": "301234567",
        "country_code": "UZ",
        "access_type": ["remote_logical", "privileged"],
        "agreement": {
          "nda": true,
          "security_clauses": true,
          "sla": true,
          "right_to_audit": false,
          "incident_notification": true
        },
        "security_certification": ["iso_27001"],
        "last_review_at": "2026-05-20",
        "concentration_risk": true
      }
    }
  ]
}
```

---

**Which fields for which class:**

| Field | hardware | software | network | service | information_resource | security_tool | information | process | personnel | site | organization | intangible |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Common core | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `technical` | **R** | **R** | **R** | **R** | **R** | **R** | — | — | — | — | — | — |
| `information` | — | — | — | — | — | — | O | — | — | — | — | — |
| `process` | — | — | — | — | — | — | — | O | — | — | — | — |
| `personnel` | — | — | — | — | — | — | — | — | O | — | — | — |
| `site` | — | — | — | — | — | — | — | — | — | O | — | — |
| `organization` | — | — | — | — | — | — | — | — | — | — | O | — |
| `intangible` | — | — | — | — | — | — | — | — | — | — | — | O |

## 4.5 Minimal asset example

```json
{
  "telemetry_type": "asset_inventory",
  "schema_version": "1.0",
  "org_id": "b3f1c2a4-1d2e-4f56-9abc-1234567890ab",
  "tlp": "RED",
  "collected_at": "2026-08-13T02:00:00Z",
  "summary": {
    "total_assets": 1284
  },
  "assets": [
    {
      "asset_uid": "web014",
      "asset_class": "hardware",
      "asset_type": "server",
      "technical": {
        "exposure": "internet_facing",
        "ip_addresses": [
          {
            "value": "203.0.113.14",
            "scope": "public"
          }
        ]
      }
    }
  ]
}
```

## 4.6 Common mistakes

| Mistake | Consequence | Correct solution |
|---|---|---|
| New `asset_uid` in every snapshot | Historical linkage is lost, "new assets" appear every day | Use a stable ID |
| `asset_uid` = IP address | The asset "disappears" when the IP changes | Normalized hostname for a technical asset (rule §2.4.7). If a CMDB ID is used, `technical.hostname` must be filled in |
| `affected_asset_uids` in the incident is in a different format or is the SOAR internal ID | The incident is not linked to the asset | The hostname of the SOAR asset, normalized according to rule §2.4.7 |
| MSSP combined several clients in one snapshot | Data is rejected | A separate request for each `org_id` |
| `asset_type` does not match the class (`hardware` + `responsible_person`) | `422` error | Check against the table in Appendix E |
| `technical` object in a `personnel` asset | `422` error — object does not match the class | Only the object of its own class |
| No `technical` or `exposure` in a technical asset | `422` error | `technical.exposure` is required |
| `name`, `email`, `login` in `personnel` | `422` — personal data is not in the schema | Only `role_category` and `represents` |
| `address` or coordinates in `site` | `422` — field does not exist | `region_code` (ISO 3166-2:UZ) |
| `privileged_access: false` + `privileged_scope` | `422` — contradictory state | Either set `true`, or remove `privileged_scope` |
| `represents: "individual"` + `headcount` | `422` — a single person has no headcount | `represents: "group"` |
| `contains_pii: false` + `pii_volume_band: "under_1k"` | `422` — contradiction | `pii_volume_band: "none"` |
| `asset_type: "personal_data"` + `confidentiality_marks: ["KT"]` | `422` — type and category do not match | Add the `PD` mark |
| `confidentiality_marks: ["OD", "KO"]` | `422` — public and confidential together | Either `["OD"]`, or restricted codes |
| `as_protection_class` on a server | `422` — only for automated systems | Record on the `information_resource/information_system` asset |
| `country_code: "uz"` | `422` — lower case | `"UZ"` — ISO 3166-1 alpha-2, upper case |
| TIN of a natural person in `org_ref` | Personal data ends up in UzCORE | Only the legal entity code |
| `"5 years"` instead of `retention_days` | `422` — type is integer | `1825` |
| `asset_uid` in `personnel` = employee name or login | Personal data ends up in UzCORE | Anonymous ID: `role-ciso`, `user-0417` |
| Treating removal from the list as "deleted" | The asset remains in the database (upsert) | Send `lifecycle_status: "decommissioned"` |
| `cvss_score` or `kev_listed` written in `known_cves` | `422` error | Only `cve_id`, `status`, `detected_at` |
| `tlp` = `AMBER` | Request is rejected | Only `RED` for assets |

---

# 5. Minimum required set

If an organization cannot implement the full schema, the following reduced set is accepted **in the first phase**. The rest is added later, and this does not break the model.

**Incident — minimal:**
```
konvert: telemetry_type · schema_version · org_id · incidents[]
element: report_id · source_case_id · tlp
lifecycle.status_id · lifecycle.detected_at · lifecycle.opened_at · lifecycle.updated_at
classification.event_category · classification.title · classification.severity_id
technical.indicators[]
```

**Alert — minimal:**
```
konvert: telemetry_type · schema_version · org_id · collected_at
element: class_uid · category_uid · activity_id · type_uid · time · severity_id
metadata.version · metadata.product.name
finding_info.uid · device.hostname
```

**Asset — minimal:**
```
konvert: telemetry_type · schema_version · org_id · tlp · collected_at · summary.total_assets
aktiv:   asset_uid · asset_class · asset_type
texnik:  technical.exposure · technical.ip_addresses · technical.os · technical.software_inventory · technical.known_cves
```

> ## Three fields that are never omitted
>
> | Field | What it provides |
> |---|---|
> | `technical.affected_asset_uids` | Links incidents to real assets (when the assets are known) |
> | `technical.indicators[].value` | Identifies cross-organization campaigns |
> | `assets[].technical.known_cves` | Triggers the national CVE early warning |
>
> 

---

# 6. Validation checklist

Before launching the integration, check the following:

**General**
- [ ] `GET /connector/me` returned a successful response
- [ ] `key` is not in the code, but in an environment variable or secret manager
- [ ] The body is serialized once: the bytes that are hashed and the bytes that are sent are exactly identical
- [ ] All times are in UTC, ISO 8601 with `Z` for incident/asset, epoch **ms** inside alerts
- [ ] `org_id` in the envelope is the organization that **owns** the data (not the sender)
- [ ] One `org_id` per request — MSSP clients are not mixed
- [ ] No `sender_id` in the body — the sender is identified via the `x-org-id` header
- [ ] No raw logs, passwords, command lines, or employee names
- [ ] The `errors` array in the `422` response is logged and read

**Incident**
- [ ] `report_id` is computed by the formula in §1.5 (not random)
- [ ] `source_case_id` is populated and does not change over the incident's lifetime
- [ ] One incident = one `report_id`, including on updates
- [ ] `related_report_ids` references only other incidents (does not include its own `report_id`)
- [ ] `tlp` is present in every incident element (not in the envelope)
- [ ] `status_id` is mapped from the source system per Appendix B.5, only within the range `1`–`5`
- [ ] `closed_at` is populated when `status_id` = `5`
- [ ] `event_type` matches the selected `event_category` (Appendix A)
- [ ] `detected_at` ≤ `opened_at` ≤ `updated_at`
- [ ] `affected_asset_uids` is populated when assets are known, with a hostname normalized per §2.4.7 rather than the SOAR internal ID; otherwise `[]`
- [ ] `indicators[].value` is refanged, lowercase, RFC 1918 filtered
- [ ] No hostnames / IPs / logins in `actions_taken` and `closing_note`
- [ ] `activity` is the full history, not only new entries
- [ ] No comment text in `activity`, only `time` and `type`
- [ ] `to_status_id` is populated in `status_changed` entries

**Alert**
- [ ] The request body is the envelope object, with the `alerts[]` array inside it
- [ ] `org_id` and `collected_at` are in the envelope, not inside the alert elements
- [ ] `class_uid`=2004, `category_uid`=2, `activity_id`=1, `type_uid`=200401
- [ ] `metadata.version` = `"1.9.0"`
- [ ] `severity_id` only from `{0,1,2,3,4,5,99}`
- [ ] `finding_info.title` is the rule name, not the event text
- [ ] `device.hostname` is normalized and equal to `asset_uid`
- [ ] `device.mac` is lowercase (`00:1a:2b:3c:4d:5e`)

**Asset**
- [ ] `tlp` = `"RED"`
- [ ] `asset_uid` is stable and does not change between snapshots
- [ ] `asset_type` matches the selected `asset_class` (Appendix E)
- [ ] Each asset contains only the object matching its class; technical classes have `technical.exposure`
- [ ] Registry objects contain only the fields from §4.4.6; dependent fields do not contradict each other (`privileged_access`/`privileged_scope`, `represents`/`headcount`, `contains_pii`/`pii_volume_band`, `confidentiality_marks`/`asset_type`, `PD`/`contains_pii`)
- [ ] No exact address in `site` — only `region_code`; `organization.org_ref` is only the legal entity's TIN (STIR)
- [ ] `asset_uid` in `personnel` assets is anonymous — no name, login, or email
- [ ] `technical.os.type_id`: Linux = **200**, Windows = **100** (Appendix B.4)
- [ ] `technical.mac_addresses[]` is lowercase — same format as alert `device.mac`
- [ ] `technical.known_cves[].cve_id` is uppercase, in `CVE-YYYY-NNNN+` format; CVSS/KEV not sent
- [ ] Decommissioned assets are sent with `lifecycle_status: "decommissioned"`

**Linkage test (the most important)**
- [ ] One test asset was selected
- [ ] Its `asset_uid` is present in the asset snapshot
- [ ] The same value is present in the incident `affected_asset_uids`
- [ ] The same value is present in the alert `device.hostname`
- [ ] All three are identical **character for character**

---

# Appendix A — ENISA RSIT incident classification (full catalog)

`classification.event_category` and `classification.event_type` are taken only from the table below. **`event_type` must belong to the selected category** — a type from another category is not accepted.

The third column shows ENISA's official spelling (with hyphens). UzCORE accepts the underscore (`_`) form and converts it internally to the ENISA form — this ensures exchange with other national CSIRTs.

### 1. `abusive_content` — abusive content

| `event_type` | ENISA spelling | Definition |
|---|---|---|
| `spam` | `spam` | Unsolicited bulk messages |
| `harmful_speech` | `harmful-speech` | Harassment, threats, defamation |
| `violence` | `violence` | Violence, illegal content involving children |

### 2. `malicious_code` — malware

| `event_type` | ENISA spelling | Definition |
|---|---|---|
| `infected_system` | `infected-system` | Infected system. **Ransomware also belongs here.** |
| `c2_server` | `c2-server` | Command and control (C&C) server |
| `malware_distribution` | `malware-distribution` | Resource distributing malware |
| `malware_configuration` | `malware-configuration` | Malware configuration |

### 3. `information_gathering` — information gathering

| `event_type` | ENISA spelling | Definition |
|---|---|---|
| `scanner` | `scanner` | Port/vulnerability scanning |
| `sniffing` | `sniffing` | Eavesdropping on network traffic |
| `social_engineering` | `social-engineering` | Social engineering (other than phishing) |

### 4. `intrusion_attempts` — intrusion attempts

| `event_type` | ENISA spelling | Definition |
|---|---|---|
| `exploit` | `exploit` | Attempt to exploit a known vulnerability |
| `brute_force` | `brute-force` | Credential brute-forcing |
| `ids_alert` | `ids-alert` | New/unknown attack signature |

### 5. `intrusions` — successful intrusion

| `event_type` | ENISA spelling | Definition |
|---|---|---|
| `privileged_account_compromise` | `privileged-account-compromise` | Privileged account compromised |
| `unprivileged_account_compromise` | `unprivileged-account-compromise` | Regular account compromised |
| `application_compromise` | `application-compromise` | Application compromised |
| `system_compromise` | `system-compromise` | System fully compromised |
| `burglary` | `burglary` | Physical intrusion |

### 6. `availability` — availability

| `event_type` | ENISA spelling | Definition |
|---|---|---|
| `dos` | `dos` | Denial of service |
| `ddos` | `ddos` | Distributed DoS |
| `misconfiguration` | `misconfiguration` | Outage caused by misconfiguration |
| `sabotage` | `sabotage` | Deliberate damage |
| `outage` | `outage` | Outage not related to an attack |

### 7. `information_content_security` — information security

| `event_type` | ENISA spelling | Definition |
|---|---|---|
| `unauthorised_information_access` | `unauthorised-information-access` | Unauthorized access |
| `unauthorised_information_modification` | `unauthorised-information-modification` | Unauthorized modification |
| `data_leak` | `data-leak` | Leak of confidential information |
| `data_loss` | `data-loss` | Data loss |

### 8. `fraud` — fraud

| `event_type` | ENISA spelling | Definition |
|---|---|---|
| `unauthorised_use_of_resources` | `unauthorized-use-of-resources` | Unauthorized use of resources (e.g. crypto-mining) |
| `copyright` | `copyright` | Copyright infringement |
| `masquerade` | `masquerade` | Acting on behalf of another person |
| `phishing` | `phishing` | Phishing |

### 9. `vulnerable` — vulnerability (a condition, not an incident)

| `event_type` | ENISA spelling | Definition |
|---|---|---|
| `weak_crypto` | `weak-crypto` | Weak cryptography |
| `ddos_amplifier` | `ddos-amplifier` | Service that can act as a DDoS amplifier |
| `potentially_unwanted_accessible` | `potentially-unwanted-accessible` | Unnecessary service left exposed |
| `information_disclosure` | `information-disclosure` | Information disclosure |
| `vulnerable_system` | `vulnerable-system` | System with a vulnerability |

### 10. `other` — other

| `event_type` | ENISA spelling | Definition |
|---|---|---|
| `other` | `other` | Does not fit any of the above |
| `undetermined` | `undetermined` | Type not yet determined |

### A.1 Practical examples — how to classify

| Situation | `event_category` | `event_type` | Additional |
|---|---|---|---|
| LockBit ransomware encrypted a server | `malicious_code` | `infected_system` | `mitre_attacks`: TA0040 → T1486 |
| SSH password brute-force attempts | `intrusion_attempts` | `brute_force` | `mitre_attacks`: TA0006 → T1110 → T1110.001 |
| SSH brute-force was **successful** | `intrusions` | `unprivileged_account_compromise` | An intrusion, not an attempt |
| Employee received a phishing email, did not click | `fraud` | `phishing` | — |
| Credentials stolen via phishing | `intrusions` | `unprivileged_account_compromise` | `mitre_attacks`: TA0001 → T1566 |
| Website under DDoS | `availability` | `ddos` | — |
| Customer database exposed to the internet | `information_content_security` | `data_leak` | `severity_id: 5` |
| Web server compromised via a CVE | `intrusions` | `application_compromise` | `mitre_attacks`: TA0001 → T1190; the CVE is linked via `alerts[]` |
| Crypto-miner found on a server | `fraud` | `unauthorised_use_of_resources` | — |
| Domain controller fully taken over | `intrusions` | `privileged_account_compromise` | `criticality: crown_jewel` |
| External address scanning ports | `information_gathering` | `scanner` | — |
| Firewall rule misconfigured, service down | `availability` | `misconfiguration` | — |

# Appendix B — OCSF 1.9.0 enum catalog

These lists are taken from `https://schema.ocsf.io/1.9.0/`. The official source always takes precedence — if in doubt, check that site.

**General rule:** `0` = Unknown, `99` = Other (does not fit the catalog). Intermediate numbers are never invented.

### B.1 `severity_id` (identical for alert and incident)

| ID | Name |
|---|---|
| `0` | Unknown — the source did not provide a severity level |
| `1` | Informational |
| `2` | Low |
| `3` | Medium |
| `4` | High |
| `5` | Critical |
| `99` | Other |

### B.2 Alert: `status_id`

| ID | Name |
|---|---|
| `0` | Unknown |
| `1` | New |
| `2` | In Progress |
| `3` | Suppressed — reviewed, found to be a false positive |
| `4` | Resolved |
| `5` | Archived |
| `99` | Other |

**Mapping from source systems:**

| Source value | `status_id` |
|---|---|
| Sentinel `New` · Defender `new` · Elastic `open` · Splunk `new` · QRadar `OPEN` | `1` New |
| Sentinel `Active` · Defender `inProgress` · Elastic `acknowledged` · Splunk `in progress` | `2` In Progress |
| QRadar `HIDDEN` · alerts closed as false positive | `3` Suppressed |
| Defender `resolved` · Splunk `resolved` | `4` Resolved |
| Sentinel `Closed` · Elastic `closed` · Splunk `closed` · QRadar `CLOSED` | `5` Archived |
| Wazuh — has no concept of status | field is not sent |

> **ATTENTION:** the alert and incident `status_id` enums are **not the same**. `3` is **Suppressed** for an alert and **On Hold** for an incident; `5` is **Archived** for an alert and **Closed** for an incident. This is how OCSF itself defines it — Detection Finding and Incident Finding are separate classes. For incidents, use the table in **Appendix B.5**.

### B.3 `observables[].type_id`

| ID | Name |
|---|---|
| `0` | Unknown |
| `1` | Hostname |
| `2` | IP Address |
| `3` | MAC Address |
| `4` | User Name |
| `5` | Email Address |
| `6` | URL String |
| `7` | File Name |
| `8` | Hash |
| `10` | Resource UID |
| `11` | Port |
| `18` | CVE Object: uid |
| `99` | Other |

### B.4 `os.type_id` — the most frequently misused enum

| ID | Name | What is included |
|---|---|---|
| `0` | Unknown | — |
| `100` | Windows | Windows 10/11, Windows Server 2016/2019/2022 |
| `101` | Windows Mobile | — |
| `200` | Linux | Ubuntu, RHEL, CentOS, Debian, SUSE, Alpine, Rocky, Alma |
| `201` | Android | Android only. Not Linux! |
| `300` | macOS | — |
| `301` | iOS | — |
| `302` | iPadOS | — |
| `400` | Solaris | — |
| `401` | AIX | — |
| `402` | HP-UX | — |
| `99` | Other | FreeBSD, Cisco IOS, proprietary OSes |

> **Only these values exist.** `1`, `102`, `202`, `203`, `403` — do not exist in OCSF and are rejected.

### B.5 Incident: `status_id` — mapping from source systems

Each organization's SOAR/SIEM system uses its own status names. Before sending to UzCORE they are **mandatorily** converted to a `status_id` number — the source text is not sent directly.

**Allowed values — only five:**

| ID | Name | Meaning |
|---|---|---|
| `1` | New | Case opened, nobody has worked on it yet |
| `2` | In Progress | An analyst is working on it |
| `3` | On Hold | Work temporarily paused — waiting for a response from an external party |
| `4` | Resolved | Technical work finished, case not formally closed |
| `5` | Closed | Case closed, `closed_at` filled in |

`0` (Unknown) and `99` (Other) are **deliberately absent**: a case is always in one of these five states.

**Extended mapping — possible spellings:**

| Source status (various spellings) | `status_id` |
|---|---|
| New · Draft · Open · Opened · Created · Pending · To Do · Unassigned · Yangi | `1` |
| In Progress · In Process · InProgress · In-Progress · Active · Investigating · Analysis · Triage · Assigned · Working · Contain · Eradicate · Recover · Jarayonda | `2` |
| On Hold · OnHold · On-Hold · Hold · Awaiting · Awaiting Caller · Awaiting Vendor · Awaiting Info · Waiting · Suspended · Paused · Deferred · Kutilmoqda | `3` |
| Resolved · Done · Remediated · Mitigated · Review · Pending Closure · Hal qilindi | `4` |
| Closed · Completed · Archive · Archived · Cancelled · Canceled · Duplicated · Rejected · Yopildi | `5` |

**By widely used systems:**

| Source system | Source status | `status_id` |
|---|---|---|
| **Microsoft Sentinel** | New | `1` |
| | Active | `2` |
| | Closed | `5` |
| **Cortex XSOAR** | Pending | `1` |
| | Active | `2` |
| | Done | `4` |
| | Archive | `5` |
| **Splunk ES** | New | `1` |
| | In Progress | `2` |
| | Pending | `3` |
| | Resolved | `4` |
| | Closed | `5` |
| **ServiceNow SecOps** | New / Draft | `1` |
| | In Progress / Analysis / Contain / Eradicate / Recover | `2` |
| | On Hold (Awaiting…) | `3` |
| | Review / Resolved | `4` |
| | Closed / Cancelled | `5` |
| **TheHive** | New | `1` |
| | InProgress | `2` |
| | Closed / Duplicated | `5` |
| **IBM QRadar SOAR** | Active | `2` |
| | Closed | `5` |
| **Kaspersky** | New | `1` |
| | In progress | `2` |
| | On hold | `3` |
| | Closed | `5` |

**Mapping rules:**

- **NIST phases do not map to `status_id`.** The Contain / Eradicate / Recover statuses in ServiceNow SecOps are all `status_id: 2` (In Progress). The technical phase is expressed in `response.containment_status`.
- **Difference between `4` Resolved and `5` Closed:** Resolved — technical work is finished, but the case is not formally closed (usually awaiting confirmation). Closed — the case is closed and `closed_at` is filled in.
- **If no matching value is found**, choose the **closest** match from the table. Sending `0` or `99` is not possible — they are rejected by the schema.
- For a system not in the list, build your own mapping table and submit it to UzCORE during onboarding.

### B.6 Incident: `verdict_id` — investigation conclusion

`verdict_id` is the conclusion reached by the analyst **after the incident has been investigated**. Difference from `status_id`: `status_id` indicates **where** the work is, while `verdict_id` indicates **what** the outcome is.

**What it gives UzCORE:** false-positive ratio by sector (if a large share of incidents are `1`, that sector's detection rules are not tuned); excluding erroneous signals from national statistics; not counting duplicates twice.

| ID | Name | When used |
|---|---|---|
| `0` | Unknown | Investigation is ongoing, no verdict yet. The usual value for open incidents. |
| `1` | False Positive | No incident occurred — the tool gave a false signal. Indicates that the rule needs tuning. |
| `2` | True Positive | A real security incident has been confirmed. |
| `3` | Disregard | Real, but disregarded — insignificant, erroneous or accidental. |
| `4` | Suspicious | Suspicious activity, but not confirmed as malicious. |
| `5` | Benign | Real activity, but harmless — e.g. work performed by the administrator, a scheduled test. |
| `6` | Test | An exercise, trial or pentest incident. Excluded from national statistics. |
| `7` | Insufficient Data | Not enough data to reach a conclusion — logs have been deleted, no access to the asset. |
| `8` | Security Risk | Not an attack, but a security problem has been identified — misconfiguration, vulnerability. |
| `9` | Managed Externally | The incident was handled by another party — provider, vendor, another SOC. |
| `10` | Duplicate | A repeat of another incident. Used together with `related_report_ids` — which indicates which incident it duplicates. |

`99` (Other) is **deliberately absent**: the eleven values above cover all practical cases.

**Mapping from source systems:**

| Source value | `verdict_id` |
|---|---|
| TheHive `TruePositive` · XSOAR `Resolved - True Positive` · Sentinel `TruePositive` | `2` |
| TheHive `FalsePositive` · Sentinel `FalsePositive` · XSOAR `False Positive` | `1` |
| TheHive `Duplicated` · XSOAR `Duplicate` | `10` |
| Sentinel `BenignPositive` · Kaspersky `Low priority` | `5` |
| TheHive `Indeterminate` · Sentinel `Undetermined` | `0` or `7` (`7` if data is insufficient) |
| Test or exercise incident · XSOAR `Test` | `6` |
| Handled by another party | `9` |

**When it is filled in:** `0` while the incident is open (or the field is omitted entirely), and the actual conclusion when it is closed. The pair `status_id: 5` with `verdict_id: 0` is a sign of unfinished work.

### B.7 Incident: `containment_status` — response phase

Indicates which phase of the NIST SP 800-61 response cycle the incident is in. Does **not duplicate** `status_id` (workflow).

| Value | Meaning |
|---|---|
| `not_contained` | Not contained, the attack is ongoing |
| `partially_contained` | Partially contained |
| `contained` | Contained, spread has been stopped |
| `eradicated` | The malicious component has been removed from the system |
| `recovered` | The system has returned to normal operation |

### B.8 Incident: `activity[].type` — timeline events

| Value | When recorded | Additional field |
|---|---|---|
| `case_opened` | Case was opened | — |
| `case_closed` | Case was closed | — |
| `case_reopened` | A closed case was reopened | — |
| `status_changed` | Status changed | `to_status_id` (required) |
| `comment_added` | A comment was written (**text is not sent**) | — |
| `task_created` | A task was created | — |
| `task_completed` | A task was completed | — |
| `severity_changed` | Severity was reassessed | `to_severity_id` (required) |
| `artifact_added` | A new IOC or piece of evidence was added | — |
| `other` | Does not match any of the above | — |

### B.9 ATT&CK tactics catalog

The attack phase is expressed via `technical.mitre_attacks[].tactic` in an incident and `finding_info.attacks[].tactic.uid` in an alert. If the source system provides only the tactic name, look up the ID in this table.

| `tactic.uid` | Name |
|---|---|
| `TA0043` | Reconnaissance |
| `TA0042` | Resource Development |
| `TA0001` | Initial Access |
| `TA0002` | Execution |
| `TA0003` | Persistence |
| `TA0004` | Privilege Escalation |
| `TA0005` | Defense Evasion |
| `TA0006` | Credential Access |
| `TA0007` | Discovery |
| `TA0008` | Lateral Movement |
| `TA0009` | Collection |
| `TA0011` | Command and Control |
| `TA0010` | Exfiltration |
| `TA0040` | Impact |

# Appendix C — Extracting fields from source systems

Practical help: where the required data is located in widely used tools.

### C.1 Where IOCs (`indicators[]`) come from

| System | Source | Filter |
|---|---|---|
| **TheHive** | Case **observables** (`dataType`, `data`, `tlp`) | Only those with `ioc: true` |
| **Cortex XSOAR** | Incident **indicators** (result of extraction rules) | By reputation/verdict |
| **Microsoft Sentinel** | Incident **entities** | Entity ≠ IOC. Exclude the victim host and user |
| **Splunk SOAR** | Container **artifacts**, CEF fields (`sourceAddress`, `fileHash`, `requestURL`) | CEF key → `type` mapping table required |
| **IBM QRadar SOAR** | **Artifacts** (IP Address, DNS Name, SHA-256, URL) | Typed, map directly |
| **Wazuh** | **No case object.** Taken from alert fields: `data.srcip`, `data.dstip`, `data.url`, `syscheck.sha256_after` | Separate mapping for each decoder |

### C.2 Core mapping from Wazuh to OCSF

| Wazuh field | OCSF field | Note |
|---|---|---|
| `id` | `finding_info.uid` | Idempotency key |
| `rule.id` | `metadata.event_code` | — |
| `rule.description` | `finding_info.title` | — |
| `rule.level` (0–15) | `severity_id` | Per the mapping table below (§3.4.3) |
| `rule.mitre.id` | `finding_info.attacks[].technique.uid` | In an incident: `technical.mitre_attacks[].techniques[].uid` |
| `rule.mitre.tactic` (name) | `finding_info.attacks[].tactic.uid` | Must be converted from name to ID — Appendix B.9 |
| `rule.firedtimes` | `count` | — |
| `timestamp` | `time` (epoch ms) | Conversion from ISO 8601 to epoch ms is required |
| `agent.name` | `device.hostname` | **In normalized form** — equal to `assets[].asset_uid` |
| `agent.ip` | `device.ip` | — |
| `data.srcip` | `observables[]` `type_id: 2` | RFC 1918 is filtered out |
| `syscheck.sha256_after` | `observables[]` `type_id: 8` | — |
| `data.vulnerability.cve` | `vulnerabilities[].cve.uid` | — |
| `full_log` | — | **Not sent** — for confidentiality reasons |

**Recommended Wazuh `rule.level` → `severity_id` mapping:**

| `rule.level` | `severity_id` | Name |
|---|---|---|
| 0–3 | `1` | Informational |
| 4–6 | `2` | Low |
| 7–9 | `3` | Medium |
| 10–12 | `4` | High |
| 13–15 | `5` | Critical |

---

# Appendix D — Official JSON Schema files

Three JSON Schema files are provided together with the document. They are written in the **JSON Schema draft 2020-12** standard and express all the rules in the document in machine-readable form.

| File | Purpose |
|---|---|
| `incident-report.schema.json` | Incident batch (envelope + `incidents[]`) |
| `alert.schema.json` | Alert batch (envelope + `alerts[]`) |
| `asset-inventory.schema.json` | Asset batch (envelope + `assets[]`): common core + class-specific object |

**What they catch:**
- RSIT `event_category` ↔ `event_type` consistency (via `if`/`then`, separately for each category)
- Conditional requirements: `closed_at` (when `status_id` is 5); `start_time` when an alert has `end_time`; for an asset, `asset_type` ↔ `asset_class` consistency and only its own object in each class (`technical` or the registry object)
- `additionalProperties: false` — fields not in the schema are rejected
- Format rules: UUID, ISO 8601 with `Z`, `CVE-YYYY-NNNN+`, CPE 2.3, MITRE `T####[.###]`
- OCSF enums: `severity_id`, `status_id`, `os.type_id`, `observables[].type_id` and others

**Rules the schema cannot catch and the server checks:** `start_time ≤ end_time`, `detected_at ≤ opened_at ≤ updated_at`, consistency of `summary` values with `assets[]`.

**Usage — Python:**

```python
import json
from jsonschema import Draft202012Validator

schema = json.load(open("incident-report.schema.json"))
validator = Draft202012Validator(schema)

errors = sorted(validator.iter_errors(payload), key=lambda e: e.path)
for e in errors:
    pointer = "/" + "/".join(str(x) for x in e.path)
    print(f"{pointer}: {e.message}")

if not errors:
    send_to_uzcore(payload)
```


---

# Appendix E — Asset taxonomy (classes and types)

The taxonomy is based on **O'zMSt 816:2025** §7.9.2 (objects of protection) and extended with **O'zMSt ISO/IEC 27005:2024**, **ISO/IEC 27001:2022 Annex A** and Resolution **ПҚ-167** of the President of Uzbekistan ([lex.uz/docs/6479190](https://lex.uz/docs/6479190)). The `asset_class` and `asset_type` values are written exactly as shown below.

**How to choose:** first determine the asset's class, then choose the most appropriate type within that class. One asset belongs to only one class. Dependencies between assets are indicated via `related_asset_uids` (O'zMSt ISO/IEC 27005:2024 A.2.2 — asset dependency graph).

The `iso27005_category` column indicates the asset's kind: **primary** — primary (information and processes), **supporting** — supporting (the resources that carry them).

**Two deliberate deviations from 816:** `source_code` — in 816 it is part of software (§7.9.2 c)3)), here it is in the `information` class, because source code is protected as information and has no network properties. `passive_network_equipment` — in 816 it is part of the network (§7.9.2 c)4)), here it is in the `site` class, because cabinets and cable ducts are physical infrastructure.

| Class | Number of types | Object |
|---|---|---|
| `information` | 12 | `information` |
| `process` | 1 | `process` |
| `hardware` | 15 | `technical` |
| `software` | 7 | `technical` |
| `network` | 5 | `technical` |
| `service` | 9 | `technical` |
| `information_resource` | 5 | `technical` |
| `security_tool` | 2 | `technical` |
| `personnel` | 6 | `personnel` |
| `site` | 5 | `site` |
| `organization` | 2 | `organization` |
| `intangible` | 1 | `intangible` |

Total: **12 classes, 70 types.**

### E.1 `information`

| `asset_type` | ISO 27005 | Description | Basis |
|---|---|---|---|
| `processed_data` | primary | Data in digital, tangible or intangible form | 816: §7.9.2 a); 27005: A.2.2; 27001: A.5.9; ПҚ-167: §11, §13 |
| `state_secret` | primary | State secrets (SS – top secret; S – secret) | 816: §7.9.2 a); Annex L; 27005: A.2.2; 27001: A.5.12 |
| `confidential_data` | primary | Confidential data (DSP – for official use; KT – commercial secret; BT – banking secret; KO – organization's confidential data) | 816: §7.9.2 a); Annex L; 27005: A.2.2; 27001: A.5.12 |
| `personal_data` | primary | Personal data (PD) | 816: §7.9.2 a); Annex L; 27005: A.2.2; 27001: A.5.34 |
| `public_data` | primary | Public data (OD) | 816: Annex L; 27005: A.2.2; 27001: A.5.12 |
| `transmitted_data` | primary | Data transmitted over communication channels | 816: §7.9.2 c)4); 27005: A.2.2; 27001: A.8.20; ПҚ-167: §12 |
| `source_code` | supporting | Source code | 816: §7.9.2 c)3); 27005: A.2.2; 27001: A.8.4 |
| `configuration` | supporting | Configuration files of systems and devices, architecture | 816: Table L.1 (9); 27005: A.2.2; 27001: A.8.9; ПҚ-167: §11–§13 |
| `backup` | supporting | Backup copies | 816: Table L.1 (1); 27005: A.2.2; 27001: A.8.13 |
| `credential` | supporting | Authentication data | 27005: A.2.2; 27001: A.5.17 |
| `cryptographic_key` | supporting | Cryptographic keys | 27005: A.2.2; 27001: A.8.24 |
| `log_data` | supporting | Audit and event logs | 27005: A.2.2; 27001: A.8.15 |

### E.2 `process`

| `asset_type` | ISO 27005 | Description | Basis |
|---|---|---|---|
| `business_process` | primary | The organization's business processes | 816: §7.9.5 c); 27005: A.2.2; 27001: A.5.30 |

### E.3 `hardware`

| `asset_type` | ISO 27005 | Description | Basis |
|---|---|---|---|
| `endpoint` | supporting | Users' end devices | 816: §7.9.2 c)1); 27005: A.2.2 (hardware); 27001: A.8.1; ПҚ-167: §11 |
| `server` | supporting | Servers | 816: §7.9.2 c)1); 27005: A.2.2 (hardware); 27001: A.8.1; ПҚ-167: §11 |
| `industrial_server` | supporting | Industrial servers (ICS) | 27005: A.2.2 (hardware); ПҚ-167: §13 |
| `storage_system` | supporting | Data storage systems | 816: §7.9.2 c)1); 27005: A.2.2 (hardware); 27001: A.7.10; ПҚ-167: §11 |
| `removable_media` | supporting | Removable storage media | 816: §7.9.2 c)1); 27005: A.2.2 (hardware); 27001: A.7.10; ПҚ-167: §6 |
| `mobile` | supporting | Mobile devices | 816: §7.9.2 c)2); 27005: A.2.2 (hardware); 27001: A.8.1; ПҚ-167: §11 |
| `atm` | supporting | ATMs | 816: §7.9.2 c)2); 27005: A.2.2 (hardware) |
| `infokiosk` | supporting | Info kiosks | 816: §7.9.2 c)2); 27005: A.2.2 (hardware) |
| `payment_terminal` | supporting | Payment terminals | 816: §7.9.2 c)2); 27005: A.2.2 (hardware) |
| `plc` | supporting | Programmable logic controllers | 27005: A.2.2 (hardware); ПҚ-167: §13 |
| `technological_equipment` | supporting | Production and technological equipment | 27005: A.2.2 (hardware); ПҚ-167: §13 |
| `iot_device` | supporting | Other standalone devices (IoT) | 816: §7.9.2 c)2); 27005: A.2.2 (hardware); 27001: A.8.1 |
| `virtual_machine` | supporting | Virtual machines | 27005: A.2.2 (hardware); 27001: A.8.9; ПҚ-167: §14 |
| `container` | supporting | Containers | 27005: A.2.2 (hardware); 27001: A.8.9; ПҚ-167: §14 |
| `media_processing_device` | supporting | Graphics, video and speech data processing equipment | 27005: A.2.2 (hardware); ПҚ-167: §11 |

### E.4 `software`

| `asset_type` | ISO 27005 | Description | Basis |
|---|---|---|---|
| `operating_system` | supporting | Operating systems | 816: §7.9.2 c)3); 27005: A.2.2 (application); 27001: A.8.19; ПҚ-167: §11–§13 |
| `application` | supporting | Application software and applications | 816: §7.9.2 c)3); 27005: A.2.2 (application); 27001: A.8.26; ПҚ-167: §11–§13 |
| `dbms` | supporting | Database management systems | 816: §7.9.2 c)3); 27005: A.2.2 (application); 27001: A.8.26; ПҚ-167: §11 |
| `diagnostic_tool` | supporting | Diagnostic software | 816: §7.9.2 c)3); 27005: A.2.2 (application); 27001: A.8.18 |
| `dev_tool` | supporting | Development tools | 816: §7.9.2 c)3); 27005: A.2.2 (application); 27001: A.8.4 |
| `utility` | supporting | Utility software | 816: §7.9.2 c)3); 27005: A.2.2 (application); 27001: A.8.18 |
| `firmware` | supporting | Firmware of hardware-software devices | 27005: A.2.2 (application); 27001: A.8.9; ПҚ-167: §11, §13 |

### E.5 `network`

| `asset_type` | ISO 27005 | Description | Basis |
|---|---|---|---|
| `corporate_network` | supporting | Corporate and/or local networks | 816: §7.9.2 c)4); 27005: A.2.2 (network); 27001: A.8.20; ПҚ-167: §12 |
| `comm_channel` | supporting | Communication channels (corporate, remote access, connections to external networks) | 816: §7.9.2 c)4); 27005: A.2.2 (network); 27001: A.8.20; ПҚ-167: §11–§13 |
| `active_network_device` | supporting | Active network equipment – switches, routers, modems | 816: §7.9.2 c)4); 27005: A.2.2 (network); 27001: A.8.20; ПҚ-167: §12 |
| `network_segment` | supporting | Network segment – VLAN, DMZ | 816: §7.17 (VLAN); 27005: A.2.2 (network); 27001: A.8.22; ПҚ-167: §12 |
| `telecom_management_system` | supporting | Telecommunications network management system | 27005: A.2.2 (network); 27001: A.8.20; ПҚ-167: §12 |

### E.6 `service`

| `asset_type` | ISO 27005 | Description | Basis |
|---|---|---|---|
| `email_system` | supporting | Email | 816: §7.9.2 c)5); §8.6.2; 27005: A.2.2 (service); 27001: A.5.14; ПҚ-167: §11 |
| `video_conferencing` | supporting | Video conferencing | 816: §7.9.2 c)5); 27005: A.2.2 (service); 27001: A.5.14 |
| `ip_telephony` | supporting | IP telephony | 816: §7.9.2 c)5); 27005: A.2.2 (service); 27001: A.5.14 |
| `messaging` | supporting | Instant messaging systems (messengers) | 816: §7.9.2 c)5); 27005: A.2.2 (service); 27001: A.5.14 |
| `edms` | supporting | Electronic document management system | 816: §7.9.2 c)5); §8.6.2; 27005: A.2.2 (service); 27001: A.5.14 |
| `identity_service` | supporting | Identification and authentication service (domain controller, IdP) | 816: Table L.1 (9); 27005: A.2.2 (service); 27001: A.5.16; ПҚ-167: §11 |
| `dns_service` | supporting | DNS service | 27005: A.2.2 (service); 27001: A.8.21 |
| `cloud_service` | supporting | Cloud services | 27005: A.2.2 (service); 27001: A.5.23 |
| `managed_service` | supporting | External provider service | 27005: A.2.2 (service); 27001: A.5.19 |

### E.7 `information_resource`

| `asset_type` | ISO 27005 | Description | Basis |
|---|---|---|---|
| `file_storage` | supporting | File storage systems (file server) | 816: §7.9.2 c)6); §8.6.2; 27005: A.2.2; 27001: A.8.3; ПҚ-167: §11 |
| `web_resource` | supporting | Internal or external web resources | 816: §7.9.2 c)6); §8.6.2; 27005: A.2.2; 27001: A.8.26; ПҚ-167: §11 |
| `database` | supporting | Local database or one that is part of an information system | 816: §7.9.2 c)6); §8.6.2; 27005: A.2.2; 27001: A.8.26; ПҚ-167: §11 |
| `information_system` | supporting | Information (automated) system | 816: §7.9.2 c); §7.9.4; 27005: A.2.2; 27001: A.8.9; ПҚ-167: §11 |
| `industrial_control_system` | supporting | Industrial control system (ICS) | 816: §7.9.3; 27005: A.2.2; ПҚ-167: §13 |

### E.8 `security_tool`

| `asset_type` | ISO 27005 | Description | Basis |
|---|---|---|---|
| `security_appliance` | supporting | Hardware information protection tools: firewall (NGFW), IDS/IPS, VPN gateway, WAF appliances (certified) | 816: §7.9.2 e); 27005: A.2.2 (hardware); 27001: A.8.20; ПҚ-167: §7, §12, §13 |
| `security_software` | supporting | Software information protection tools: EDR, antivirus, DLP, SIEM agents (certified) | 816: §7.9.2 e); 27005: A.2.2 (application); 27001: A.8.7; ПҚ-167: §7, §12, §13 |

### E.9 `personnel`

| `asset_type` | ISO 27005 | Description | Basis |
|---|---|---|---|
| `employee` | supporting | Organization employees | 816: §7.9.2 b); 27005: A.2.2 (human resource); 27001: A.6.1; ПҚ-167: §4 |
| `customer` | supporting | Customers | 816: §7.9.2 b); 27005: A.2.2 (human resource) |
| `user` | supporting | Users (internal and external – customers, partners, Internet users) | 816: §7.9.2 b); Annex L; 27005: A.2.2 (human resource); 27001: A.5.18 |
| `developer` | supporting | Developers | 816: §7.9.2 b); 27005: A.2.2 (human resource); 27001: A.8.25 |
| `administrator` | supporting | Administrators (privileged users) | 27005: A.2.2 (human resource – administrator); 27001: A.8.2 |
| `responsible_person` | supporting | Person or unit responsible for information security | 816: §7.15; 27005: A.2.2 (human resource); 27001: A.5.2; ПҚ-167: §4, §5 |

### E.10 `site`

| `asset_type` | ISO 27005 | Description | Basis |
|---|---|---|---|
| `office_room` | supporting | Protected office and meeting rooms | 816: §7.9.2 d); 27005: A.2.2; 27001: A.7.1 |
| `server_room` | supporting | Server rooms, switching rooms | 816: §7.9.2 d); 27005: A.2.2; 27001: A.7.4 |
| `backup_storage_room` | supporting | Rooms where backup media, copies and archives are stored (storerooms, archives) | 816: §7.9.2 d); 27005: A.2.2; 27001: A.7.10 |
| `datacenter` | supporting | Data center | 816: §7.9.2 d); 27005: A.2.2; 27001: A.7.4 |
| `passive_network_equipment` | supporting | Passive network equipment – mounting cabinets, cable ducts, patch panels | 816: §7.9.2 c)4); 27005: A.2.2 (network); 27001: A.7.12; ПҚ-167: §12 |

### E.11 `organization`

| `asset_type` | ISO 27005 | Description | Basis |
|---|---|---|---|
| `supplier` | supporting | External operator or supplier | 816: §8.6.13; 27005: A.2.2; 27001: A.5.19 |
| `org_unit` | supporting | Organizational unit (as asset owner) | 816: §8.6.10; 27005: A.2.2; 27001: A.5.2 |

### E.12 `intangible`

| `asset_type` | ISO 27005 | Description | Basis |
|---|---|---|---|
| `reputation` | primary | The organization's reputation and image | 816: §7.9.2 f); 27005: A.2.2 |

---

**Contact:** for technical questions and integration support, contact UzCORE.
*(Contact details will be added when the document is finalized.)*

