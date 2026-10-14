# UzCORE / nSOC telemetry docs

Bitta sahifali hujjat sayti: qo'llanma + 3 ta sxemaning maydon ma'lumotnomasi + avtomatik changelog + versiyalar arxivi.
Sayt `dist/index.html` ga quriladi va GitHub Pages'ga avtomatik chiqadi.

## Qayerda nima yashaydi (haqiqat manbasi)

| Fayl | Nima uchun | Kim tahrirlaydi |
|---|---|---|
| `schemas/*.schema.json` | Maydonlar, turlar, R/O, enum, qoidalar. **Maydon jadvallari shundan generatsiya qilinadi** — docx/md da qayta yozilmaydi. | Sxema o'zgarganda |
| `docs/guide.uz.md` | Qo'llanma matni (asl nusxa). `guide.en.md`, `guide.ru.md` bo'lsa shu tilda ko'rsatiladi, bo'lmasa UZ ko'rsatiladi. | Matn o'zgarganda |
| `i18n/schema.en.json`, `i18n/schema.ru.json` | Sxemadagi `description` larning tarjimasi. Kalit: `<sxema>#<json-pointer>`. Tarjima yo'q bo'lsa UZ ko'rsatiladi va "UZ" belgisi qo'yiladi. | Tarjimon |
| `i18n/ui.json` | Sayt interfeysi matnlari (3 til). | Kamdan-kam |
| `releases/<versiya>/` | Reliz paytidagi snapshot. **Qo'lda tegilmaydi.** Changelog ikki snapshotni solishtirishdan hisoblanadi. | `build.py release` |

## Kundalik ish

```bash
pip install markdown jsonschema        # bir marta

# 1. schemas/ yoki docs/ dagi faylni tahrirlang
# 2. tekshiring — sxema validmi, tarjima kaliti eskirmadimi, nima o'zgardi:
python build.py check
# 3. lokal ko'ring:
python build.py && start dist/index.html     # Windows
# 4. git commit + push  →  GitHub Pages o'zi qayta quradi
```

Reliz qilinmagan o'zgarishlar sahifada **DRAFT** banneri bilan ko'rinadi, changelog'ning birinchi yozuvida
"Unreleased" sifatida maydonma-maydon ro'yxat chiqadi. Bu tashkilotlarga ko'rsatishdan oldin ko'rib chiqish uchun.

## Reliz

```bash
python build.py release 1.1.0 "asset: information.retention_days qo'shildi; incident: closing_note maxLength 4000"
git add -A && git commit -m "release 1.1.0" && git push
```

Reliz nima qiladi:
- `releases/1.1.0/` ga schemas/, docs/, i18n/ nusxasi + `meta.json` (sana, izoh)
- Changelog'da `v1.1.0` yozuvi: oldingi reliz bilan avtomatik diff (qo'shilgan / olib tashlangan / o'zgargan maydonlar, qo'llanmaning qaysi bo'limi yangilangani)
- Har yangi maydon yonida `1.1.0` belgisi ("shu versiyada qo'shilgan")
- `dist/versions/1.1.0/index.html` — o'sha paytdagi to'liq sahifa, doimiy havola
- `dist/schemas/1.1.0/*.schema.json` — validatorga berish uchun xom sxema fayllari

Versiya raqami: `MAJOR.MINOR.PATCH`. Maydon olib tashlansa yoki R/O qattiqlashsa — MAJOR; maydon qo'shilsa — MINOR; faqat matn/tarjima — PATCH.
Sxema ichidagi `schema_version` (`"1.0"`) payload versiyasi — u hujjat versiyasidan alohida va faqat mos kelmaydigan o'zgarishda ko'tariladi.

## GitHub Pages sozlash (bir marta)

1. Repo → Settings → Pages → Source: **GitHub Actions**.
2. `main` ga push qiling. 1–2 daqiqada `https://<user>.github.io/uzcore-docs/` da chiqadi.
3. Sxemalardagi `$id` manzilini (`https://uzcore.csec.uz/schemas/1.0/...`) xohlasangiz shu Pages manziliga yo'naltirish mumkin — `dist/schemas/<ver>/` aynan shu fayllarni beradi.

## Tarjima qo'shish

- Sxema ta'riflari: `i18n/schema.en.json` ga kalit qo'shing. Kalitlar ro'yxatini `python build.py check` chiqaradi (tarjima qilinmaganlari).
- Qo'llanma: `docs/guide.en.md` yarating — bo'lgan zahoti EN tugmasi shu faylni ko'rsatadi. Bo'limlar tuzilishi (sarlavhalar) uz bilan bir xil bo'lsa changelog ham ishlaydi.
