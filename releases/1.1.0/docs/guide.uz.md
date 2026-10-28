# Milliy SOC (UzCORE) — Ma'lumotlarni yuborish bo'yicha texnik qo'llanma

**Versiya:** 1.0
**Sana:** 2026-09-28
**Holati:** Tashkilotlarga yuborish uchun
**Standartlar:** OCSF 1.9.0 (Detection Finding 2004 + Incident Finding 2005) · ENISA RSIT 1.3 · EU NIS 2 taksonomiyasi · MITRE ATT&CK · CVE / CPE 2.3 · TLP 2.0 · O'zMSt 816:2025 · O'zMSt ISO/IEC 27005:2024 · O'z DSt 2814:2014 · ISO 8601 · RFC 4122 (UUID)

---

## 0. Hujjat haqida

### 0.1 Ma'lumotni yuborish

Ushbu hujjatdagi quyida keltirilgan namuna JSON shakldagi ma'lumotlarni to'gridan-to'g'ri API orqali yuborilishi ko'zda tutilgan.


### 0.2 Yuboriladigan ma'lumotlar turi

UzCORE tashkilotlardan quyidagi turdagi ma'lumotlarni qabul qiladi:

| # | Telemetriya | Manba tizimi | Yuborish rejimi | Maxfiylik |
|---|---|---|---|---|
| 1 | **Incident Report** — tasdiqlangan xavfsizlik hodisasi | SOAR / Case-management (TheHive, XSOAR, Sentinel, QRadar SOAR) | Hodisa ochilganda + har bir muhim yangilanishda | TLP bo'yicha, odatda AMBER |
| 2 | **Alert** — bitta vositaning aniqlashi | SIEM / EDR / IDS (Wazuh, Splunk, Elastic) | Real vaqtda yoki batch (≤5 daqiqa) | AMBER |
| 3 | **Asset Inventory** — aktivlar ro'yxati | SIEM / inventarizatsiya vositasi | Interval bo'yicha snapshot (kuniga 1 marta) | **TLP:RED** |


---

## 1. Umumiy texnik qoidalar

### 1.1 Transport va endpointlar

Barcha so'rovlar: `HTTPS`, `Content-Type: application/json`, `UTF-8` kodlash.

| Metod | Endpoint | Nima qiladi |
|---|---|---|
| `GET` | `/connector/me` | Autentifikatsiyadan o'tgan subyektning tashkilot profilini qaytaradi |
| `POST` | `/connector/bulk-incidents` | Incident hisobotlari to'plamini yuborish |
| `POST` | `/connector/bulk-alerts` | Alertlar to'plamini yuborish |
| `POST` | `/connector/bulk-assets` | Aktivlar snapshotini yuborish |


### 1.2 Autentifikatsiya — HMAC-SHA256 imzo

Har bir so'rov **maxfiy kalit bilan lokal imzolanadi** va kalitning o'zi hech qachon tarmoqqa chiqmaydi.

#### 1.2.1 Tashkilotni ro'yxatdan o'tkazish

Kiberxavfsizlik markazi ma'muriyati bilan bog'lanib, tashkilotingiz uchun ikkita qiymatni olasiz:

| Qiymat | Nima uchun |
|---|---|
| `organizationId` | Tashkilotingizni aniqlaydi. Har bir so'rovda `x-org-id` header'i orqali yuboriladi. |
| `key` | Maxfiy kalit. **Hech qachon serverga yuborilmaydi** — faqat sizning tomoningizda qoladi va so'rovlarni lokal imzolash uchun ishlatiladi. |

#### 1.2.2 Ma'lumotlarni saqlash

`key` — parol darajasidagi maxfiy ma'lumot:

- Kod ichiga yozilmaydi va Git ga tushmaydi.
- Muhit o'zgaruvchisi, secret manager yoki shifrlangan konfiguratsiya faylida saqlanadi.
- Faylda saqlansa, ruxsatlar `0600` bo'ladi.
- Log ga, xatolik xabariga yoki trace ga chiqarilmaydi.

Kalit sizib chiqqan deb gumon qilsangiz, darhol Kiberxavfsizlik markaziga murojaat qilish so'raladi.

#### 1.2.3 So'rovni imzolash

Har bir so'rov HMAC-SHA256 bilan imzolanadi.

| Header | Qiymat |
|---|---|
| `x-org-id` | `organizationId` |
| `x-timestamp` | So'rov vaqti, epoch sekundda |
| `x-nonce` | Har so'rov uchun tasodifiy satr (takroriy hujumga qarshi) |
| `x-signature` | HMAC-SHA256 natijasi, kichik harfli hex |


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

#### 1.2.4 Tekshirish va ishga tushirish

Haqiqiy ma'lumot yuborishdan **oldin** integratsiyani tasdiqlang:

```
GET /connector/me
```

Imzo to'g'ri bo'lsa, server tashkilotingiz profilini qaytaradi. Boshqa har qanday javob — header yoki imzoning o'zida xatolik borligini bildiradi.


### 1.3 `org_id` — eng ko'p xato qilinadigan joy

Har bir yozuvda **ikkita identifikator** bor va ular bir xil bo'lishi shart emas:

| Joy | Maydon | Ma'nosi |
|---|---|---|
| HTTP header | `x-org-id` | **Kim yubordi** — autentifikatsiyadan o'tgan tashkilot. Odatda hududiy SOC yoki MSSP. |
| Payload tanasi | `org_id` | **Kim haqida** — hodisa yuz bergan yoki ma'lumot tegishli bo'lgan tashkilot. |

Backend ikkalasini shu tarzda ajratadi: imzo `x-org-id` bilan tekshiriladi, ma'lumot esa tanadagi `org_id` ga yoziladi. **Tanada `sender_id` yuborilmaydi** — yuboruvchi allaqachon header va imzo orqali aniqlangan.

Uchta ssenariy:

```
1. Tashkilot o'zi yuboradi:
   header  x-org-id = org-A
   tana    org_id   = org-A            ← ikkalasi bir xil

2. Hududiy SOC a'zosi nomidan yuboradi:
   header  x-org-id = sector-soc-finance
   tana    org_id   = org-bank-014     ← har xil

3. MSSP mijozi nomidan yuboradi:
   header  x-org-id = mssp-alpha
   tana    org_id   = org-clinic-007   ← har xil
```

**MSSP uchun alohida talab:** bir nechta mijozning ma'lumoti bitta payloadda aralashtirilmaydi. Har bir `org_id` uchun alohida so'rov yuboriladi. Aralashgan (attribusiya qilib bo'lmaydigan) ma'lumot rad etiladi.

### 1.4 Vaqt formatlari — DIQQAT, ikki xil

| Telemetriya | Format | Misol |
|---|---|---|
| Incident Report | **ISO 8601**, UTC, `Z` bilan | `"2026-08-13T09:12:44Z"` |
| Asset Inventory | **ISO 8601**, UTC, `Z` bilan | `"2026-08-13T02:00:00Z"` |
| Alert — `collected_at` | **ISO 8601**, UTC | `"2026-08-13T09:15:00Z"` |
| Alert — OCSF ichki maydonlari (`time`, `start_time`, `end_time`, `metadata.logged_time`) | **epoch millisekund** (integer) | `1786594364512` |

Konvertatsiya:

```python
# ISO -> epoch ms
import datetime
dt = datetime.datetime(2026, 8, 13, 4, 12, 44, 512000, tzinfo=datetime.timezone.utc)
epoch_ms = int(dt.timestamp() * 1000)   # 1786594364512

# epoch ms -> ISO
datetime.datetime.fromtimestamp(1786594364512/1000, datetime.timezone.utc).isoformat()
```

### 1.5 Idempotentlik va `report_id` generatsiyasi

Tarmoq uzilib qolsa yoki javob kelmasa, **xuddi shu payloadni qayta yuboring**. 

| Telemetriya | Idempotentlik kaliti |
|---|---|
| Incident | `report_id` |
| Alert | `org_id` + `metadata.product.name` + `finding_info.uid` |
| Asset | `org_id` + `asset_uid` (upsert, §4.2) |


#### 1.5.1 Determinlashtirilgan UUID v5

**`report_id` saqlanmaydi, u har safar qayta hisoblanadi.** Kirish ma'lumotlari bir xil bo'lsa, natija ham har doim bir xil bo'ladi.

UUID v5 (RFC 4122 §4.3) — nom asosidagi, SHA-1 dan foydalanadigan determinlashtirilgan UUID.

```
report_id = uuidv5(UzCORE_NAMESPACE, org_id + "|" + source_case_id)
```

**UzCORE namespace UUID (barcha tashkilotlar uchun bir xil, o'zgarmaydi):**

```
17e9f2a9-2473-5a70-b622-f121ae871cb0
```

**Ishlangan misol:**

```
org_id          = b3f1c2a4-1d2e-4f56-9abc-1234567890ab
source_case_id  = CASE-2026-0441
nom satri       = "b3f1c2a4-1d2e-4f56-9abc-1234567890ab|CASE-2026-0441"

report_id       = 8f339179-64ae-5763-99ab-2a0c6562203e
```

Boshqa case:

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


#### 1.5.2 Normallashtirish qoidalari — majburiy

Determinizm faqat kirish satri **belgima-belgi** bir xil bo'lgandagina ishlaydi:

| Qoida | Sabab |
|---|---|
| `org_id` — kichik harfga o'giriladi, bo'sh joy olib tashlanadi | UUID lar ba'zan katta harfda yoziladi |
| `source_case_id` — faqat bo'sh joy olib tashlanadi, **registr o'zgartirilmaydi** | Case ID lari registr-sezgir (`CASE-441` ≠ `case-441`) |
| Ajratgich — har doim `\|` (vertikal chiziq) | `-` yoki `:` case ID ichida uchrashi mumkin |

#### 1.5.3 Shu sababli `source_case_id` — MAJBURIY

Har bir SOAR/case tizimida bu qiymat bor:

| Tizim | Maydon |
|---|---|
| TheHive | `case.caseId` yoki `case._id` |
| Cortex XSOAR | `incident.id` |
| Microsoft Sentinel | `incident.properties.incidentNumber` |
| Splunk SOAR | `container.id` |
| IBM QRadar SOAR | `incident.id` |
| ServiceNow SecOps | `sn_si_incident.number` |


### 1.6 Javob kodlari va xatolik formati

UzCORE xatoliklarni **RFC 9457 (Problem Details for HTTP APIs)** standarti bo'yicha qaytaradi.

Javob sarlavhasi: `Content-Type: application/problem+json`

**Standart maydonlar (RFC 9457 §3.1):**

| Maydon | Ta'rif |
|---|---|
| `type` | Muammo turini bildiruvchi URI. UzCORE uchun: `https://uzcore.csec.uz/problems/<slug>` |
| `title` | Qisqa, inson o'qiy oladigan sarlavha. Bir xil `type` uchun o'zgarmaydi. |
| `status` | HTTP status kodi (javobdagi kod bilan bir xil) |
| `detail` | Aynan shu holat uchun tushuntirish |
| `instance` | Shu konkret so'rovni bildiruvchi URI |

**UzCORE qo'shimchasi (extension member):** `errors[]` massivi — har bir maydon uchun alohida xatolik. RFC 9457 §3.2 kengaytma maydonlariga ruxsat beradi.

Massiv elementining tuzilishi JSON Schema 2020-12 standart chiqish formatiga mos:

| Maydon | Ta'rif |
|---|---|
| `pointer` | **RFC 6901 JSON Pointer** — payloaddagi muammoli maydonning aniq manzili |
| `code` | Mashina o'qiy oladigan xatolik kodi |
| `detail` | Tushuntirish |
| `allowed` | Enum xatoliklarida — ruxsat etilgan qiymatlar ro'yxati |

**Misol — `422`:**

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

**Massiv ichidagi element uchun `pointer`** massiv indeksini o'z ichiga oladi:

```json
{
  "pointer": "/assets/12/technical/known_cves/0/cve_id",
  "code": "format_invalid",
  "detail": "CVE identifikatori 'CVE-YYYY-NNNN+' formatida, katta harflarda bo'lishi kerak."
}
```

**Xatolik kodlari (`code`):**

| Kod | Ma'nosi |
|---|---|
| `required` | Majburiy maydon yo'q |
| `enum_mismatch` | Qiymat ruxsat etilgan ro'yxatda yo'q |
| `type_mismatch` | Ma'lumot turi noto'g'ri (masalan string o'rniga integer) |
| `format_invalid` | Format buzilgan (UUID, ISO 8601, CVE, CPE) |
| `out_of_range` | Son ruxsat etilgan diapazondan tashqarida |
| `too_long` | Satr yoki massiv chegaradan uzun |
| `unknown_field` | Sxemada yo'q maydon (`additionalProperties: false`) |
| `conditional_required` | Shart bajarilgani uchun majburiy bo'lib qolgan maydon yo'q |
| `cross_field_conflict` | Maydonlar bir-biriga zid (masalan `detected_at` > `opened_at`) |
| `forbidden_field` | Yuborilishi taqiqlangan maydon (`metadata.tenant_uid`) |


### 1.7 TLP 2.0 — maxfiylik darajasi

Har bir yozuv `tlp` qiymatini olib yuradi. UzCORE shu qiymatga qarab kim ko'rishi va tarqatilishini hal qiladi.

| Qiymat | Ma'nosi | Qachon ishlatiladi |
|---|---|---|
| `CLEAR` | Cheklovsiz tarqatiladi | Ommaviy ma'lumot |
| `GREEN` | Hamjamiyat ichida | IOC lar, boshqa tashkilotlar himoyalanishi uchun |
| `AMBER` | Faqat tashkilot va uning mijozlari | Standart holat — ko'pchilik hodisalar |
| `AMBER+STRICT` | Faqat tashkilot ichida | Sezgir hodisalar |
| `RED` | Faqat nomma-nom oluvchilar | Aktivlar inventarizatsiyasi (majburiy) |

Incident uchun `AMBER`, asset inventory uchun `RED` (majburiy, boshqa qiymat qabul qilinmaydi).

---

# 2. Incident Report — tasdiqlangan hodisa

## 2.1 Ta'rif

Tashkilotning SOAR / case-management tizimida **ish (case) ochilgan** tasdiqlangan xavfsizlik hodisasi. Bu vositaning signali emas — bu analitik ko'rib chiqib, haqiqiy deb tasdiqlagan va javob choralari boshlangan hodisa.

**Manba:** TheHive, Cortex XSOAR, Microsoft Sentinel, Splunk SOAR (Phantom), IBM QRadar SOAR, ServiceNow SecOps.

## 2.2 Qachon yuboriladi

Bir hodisa hayoti davomida **bir necha marta** yuboriladi va har safar **bir xil `report_id`** ishlatiladi:

```
  Case ochildi          →  status_id: 1 (New)
  Tergov boshlandi      →  status_id: 2 (In Progress)
  Vendor javobi kutildi →  status_id: 3 (On Hold)
  Hal qilindi           →  status_id: 4 (Resolved)
  Yopildi               →  status_id: 5 (Closed)  +  closed_at
```

Bu birinchi yuborishmi yoki yangilanishmi — **alohida belgilanmaydi**. Server `report_id` bo'yicha o'zi aniqlaydi: bazada bor bo'lsa yangilanish, yo'q bo'lsa yangi hodisa.

**Yangilanish yuborish majburiy bo'lgan holatlar:**
- `lifecycle.status_id` o'zgardi
- `classification.severity_id` o'zgardi
- `lifecycle.verdict_id` belgilandi yoki o'zgardi
- Yangi IOC yoki yangi ta'sirlangan aktiv qo'shildi
- `response.containment_status` o'zgardi

Boshqa mayda o'zgarishlar uchun yangilanish yuborish shart emas.

**Muddat:** `critical` va `high` darajali hodisalar aniqlangandan keyin **1 soat ichida**, qolganlari **24 soat ichida** yuboriladi.

## 2.3 To'liq JSON misol

Konvert `org_id` ni bir marta olib yuradi; hodisalar `incidents[]` massivida. Quyida bitta hodisali to'plam:

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

## 2.4 Maydonlar

### 2.4.1 Maydonlarni belgilash tizimi

Har bir maydon jadvalida `R/O` ustuni bor:

| Belgi | Ma'nosi |
|---|---|
| **R** | **Required** — majburiy. Bu maydonsiz payload `422` bilan rad etiladi. |
| **C** | **Conditional** — shartli majburiy. Qachon majburiy bo'lishi maydon izohida yozilgan. |
| **O** | **Optional** — ixtiyoriy. Tashkilotda bu ma'lumot bo'lsa yuboriladi. |
| **R\*** | Massiv **ichidagi** har bir element uchun majburiy. Massivning o'zi ixtiyoriy bo'lishi mumkin. |
| **STD** | Qiymat **standart katalogdan** olinadi (OCSF, RSIT, MITRE, CVE). O'ylab topilmaydi. Ro'yxat ilovalarda. |

### 2.4.2 Standartlarga havolalar

| Standart | Versiya | Egasi | Qayerda ko'rish |
|---|---|---|---|
| **OCSF** (Open Cybersecurity Schema Framework) | 1.9.0 | Linux Foundation | `https://schema.ocsf.io/1.9.0/` |
| **ENISA RSIT** (Reference Security Incident Taxonomy) | 1.3 | ENISA / TF-CSIRT | `https://github.com/enisaeu/Reference-Security-Incident-Taxonomy-Task-Force` |
| **EU NIS 2** ta'sir taksonomiyasi | — | NIS Cooperation Group | Ta'sir bloki uchun |
| **MITRE ATT&CK** | Enterprise v15+ | MITRE | `https://attack.mitre.org/` |
| **CVE** | — | MITRE / NVD | `https://nvd.nist.gov/` |
| **CPE** | 2.3 | NIST | `https://nvd.nist.gov/products/cpe` |
| **TLP** | 2.0 | FIRST | `https://www.first.org/tlp/` |


### 2.4.3 Konvert (envelope) — kim va qachon

Bu maydonlar **butun to'plamga** tegishli va bir marta yoziladi. Backend delegatsiyani aynan shu `org_id` bo'yicha tekshiradi — massivda necha yuz hodisa bo'lishidan qat'i nazar, bitta tekshiruv.

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `telemetry_type` | string | **R** | Qat'iy qiymat: `"incident_batch"`. Payloadni to'g'ri quvurga yo'naltiradi. |
| `schema_version` | string | **R** | Ushbu hujjat versiyasi. Hozir: `"1.0"`. |
| `org_id` | UUID | **R** | Hodisalar yuz bergan tashkilot — **ma'lumot egasi** (§1.3). Bitta so'rovda bitta tashkilot. |
| `collected_at` | timestamp | **O** | To'plam integratsiya tomonidan shakllantirilgan vaqt. **ISO 8601 UTC.** Diagnostika maydoni — quyidagi izohga qarang. |
| `incidents` | array | **R** | 1–200 ta incident obyekti |

**`collected_at` nima uchun kerak va qanday ishlatiladi:**

Bu maydon hodisa haqida emas, **integratsiya haqida** ma'lumot beradi. Uning ikkita amaliy vazifasi bor:

| Vazifa | Qanday hisoblanadi | Nima ko'rsatadi |
|---|---|---|
| Yetkazib berish kechikishi | `collected_at − lifecycle.updated_at` | Case SOAR da yangilanganidan keyin UzCORE ga yetib kelguncha qancha vaqt o'tgani. Katta farq konnektor sekinlashganini yoki navbatda qolib ketganini bildiradi. |
| Integratsiya tiriklik belgisi | Oxirgi `collected_at` qiymati | Tashkilotning integratsiyasi oxirgi marta qachon ishlaganini ko'rsatadi — hodisa bo'lmagan kunlarda ham. |

To'ldirilmasa, UzCORE so'rov qabul qilingan vaqtni ishlatadi. U ham ishlaydi, lekin aniqligi pastroq: tarmoq kechikishi va server navbatini ham o'z ichiga oladi, ya'ni konnektor muammosi bilan tarmoq muammosini ajratib bo'lmaydi.

### 2.4.4 `incidents[]` elementi — identifikatsiya

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `report_id` | UUID v5 | **R\*** | Hodisaning barqaror identifikatori. **§1.5 formulasi bo'yicha hisoblanadi**, tasodifiy generatsiya qilinmaydi. Hodisa hayoti davomida o'zgarmaydi. |
| `source_case_id` | string | **R\*** | Tashkilotning o'z case raqami. **`report_id` shundan hisoblanadi (§1.5), shuning uchun majburiy.** Hodisa hayoti davomida o'zgarmaydi. |
| `source_system` | string | **O** | Case tizimi nomi: `"TheHive"`, `"XSOAR"`, `"Sentinel"`, `"Splunk SOAR"`, `"QRadar SOAR"`, `"Updive"`. |
| `tlp` | enum | **R\*** | `CLEAR` │ `GREEN` │ `AMBER` │ `AMBER+STRICT` │ `RED`. Odatdagi qiymat: `AMBER`. |
| `related_report_ids` | array[UUID] | **O** | Analitik shu hodisa bilan **bog'liq deb hisoblagan boshqa hodisalarning** `report_id` lari. Batafsil: quyida. |
| `alerts` | array[string] | **O** | Ushbu hodisaga bog'langan alertlarning `finding_info.uid` qiymatlari. Joylashuvi: `incidents[]` elementining **o'zida**, `lifecycle` va `technical` bloklari bilan bir darajada. Alert telemetriyasi bilan bog'laydi va CVE zanjirini ochadi. |

**`related_report_ids` — qachon ishlatiladi:**

Bu maydon **faqat** analitik ikkita alohida caseni bir-biriga bog'liq deb hisoblaganda to'ldiriladi. Tipik holatlar:

- Bitta hujum ikkita caseda ochilgan (dublikat), biri ikkinchisiga birlashtirildi
- Bitta kampaniyaning bir necha bosqichi alohida caselarda kuzatilgan
- Oldingi hodisa to'liq yopilmagani sababli yangisi kelib chiqqan

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

Bu misolda `verdict_id: 10` (Duplicate) hodisa dublikat ekanini, `related_report_ids` esa **qaysi** hodisaga dublikat ekanini aytadi. Ikkalasi birga ishlaydi: UzCORE dublikatni milliy statistikadan chiqarib tashlaydi, lekin bog'lanishni saqlab qoladi.

### 2.4.5 `lifecycle` — hodisa hayoti va javob tezligi

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `detected_at` | timestamp | **R\*** | Tashkilot vositasi faoliyatni **birinchi aniqlagan** vaqt — case ochilgan vaqt emas. Odatda eng erta alertning vaqti. Barcha `time_to_*` hisoblarining boshlang'ich nuqtasi. |
| `opened_at` | timestamp | **R\*** | SOAR da case ochilgan vaqt. `opened_at − detected_at` = triaj kechikishi. |
| `updated_at` | timestamp | **R\*** | Aynan shu hisobot versiyasi shakllangan vaqt. Har yangilanishda o'zgaradi. |
| `closed_at` | timestamp | **C** | Case yopilgan vaqt. **`status_id` = `5` bo'lganda majburiy.** Aks holda `null`. |
| `time_to_acknowledge_sec` | integer | **O** | MTTA: `detected_at` dan birinchi analitik harakatigacha, sekundda. |
| `time_to_contain_sec` | integer | **O** | MTTC: `detected_at` dan lokalizatsiyagacha, sekundda. |
| `time_to_resolve_sec` | integer | **O** | MTTR: `detected_at` dan to'liq hal qilishgacha, sekundda. |
| `verdict_id` | integer | **O · STD** | Tergovdan keyingi xulosa. To'liq ro'yxat va mapping: **Ilova B.6**. |

> Case har doim shu beshta holatdan birida bo'ladi. Agar manba tizimning holati ro'yxatda bo'lmasa, **Ilova B.5** jadvalidan eng yaqin mos keluvchisini tanlang.

**`time_to_*_sec` — hisoblash qoidasi:**

Uchala qiymat ham **`detected_at` dan** boshlab hisoblanadi, `opened_at` dan emas. Bu qoida majburiy: agar tashkilotlar har xil boshlang'ich nuqta ishlatsa, milliy MTTR ko'rsatkichi taqqoslab bo'lmaydigan bo'lib qoladi.

```
time_to_acknowledge_sec = birinchi_analitik_harakati − detected_at
time_to_contain_sec     = lokalizatsiya_vaqti      − detected_at
time_to_resolve_sec     = hal_qilingan_vaqt        − detected_at
```

Qiymatlar SOAR ma'lumoti asosida to'ldiriladi. Agar tizim kerakli vaqtni bermasa, maydonni `null` qoldiring — taxminiy qiymat yubormang.

### 2.4.6 `classification` — hodisa turi (ENISA RSIT)

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `event_category` | enum | **R\* · STD** | RSIT birinchi daraja — 10 ta qiymat. To'liq ro'yxat: **Ilova A**. |
| `event_type` | enum | **O · STD** | RSIT ikkinchi daraja. **Tanlangan kategoriyaga mos bo'lishi shart.** To'liq ro'yxat: **Ilova A**. |
| `title` | string | **R\*** | Qisqa sarlavha, 3–120 belgi. Maxfiy ma'lumot yozilmaydi. |
| `description` | string | **O** | Tozalangan xulosa, ≤2000 belgi. IP, foydalanuvchi nomi, buyruq qatori, xom log kiritilmaydi. |
| `severity_id` | integer | **R\* · STD** | `0` Unknown · `1` Informational · `2` Low · `3` Medium · `4` High · `5` Critical · `99` Other. **Alert telemetriyasi bilan bir xil shkala.** |

> **`event_type` nima uchun ixtiyoriy:** hech bir SOAR tizimida RSIT taksonomiyasi yo'q, ya'ni bu qiymat har doim qo'lda tanlanadi. 35 ta turdan noto'g'risini tanlashdan ko'ra bo'sh qoldirish yaxshiroq — milliy statistikada kategoriya darajasidagi rasm baribir to'g'ri qoladi.

### 2.4.7 `technical` — hujumchi xatti-harakati

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `mitre_attacks` | array[object] | **O · STD** | MITRE ATT&CK taktikalari, har biri ostida texnikalar, ular ostida subtexnikalar. Struktura quyida. |
| `affected_asset_uids` | array[string] | **O** | Ta'sirlangan aktivlarning `asset_uid` qiymatlari. Aktivlar inventarizatsiyasidagi `assets[].asset_uid` bilan bir xil yozilishi shart. Bu maydon aktivlar bilan bog'lanishning yagona yo'li. Aktivlar ma'lum bo'lganda to'ldiriladi. Hech qanday ichki aktiv ishtirok etmagan yoki ko'lam hali aniqlanmagan bo'lsa, `[]` yuboriladi va keyingi lifecycle yangilanishida to'ldiriladi. |
| `indicators` | array[object] | **R\*** | IOC lar. Struktura quyida. Bo'sh massiv (`[]`) faqat manba tizimda hech qanday observable bo'lmagan holatda ruxsat etiladi. |

#### `affected_asset_uids` — SOAR aktiv ID si emas, hostname

SOAR tizimlari ta'sirlangan aktivni o'zining ichki yozuv ID si bilan saqlaydi (masalan FortiSOAR asset ID `a3f9…`). Bu ID UzCORE ga **yuborilmaydi**: UzCORE da bunday aktiv yo'q va bog'lanish yo'qoladi. Uning o'rniga SOAR aktivining **hostname** atributi olinadi va quyidagi qoida bo'yicha normallashtiriladi.

**Normallashtirish qoidasi** — texnik aktivning `asset_uid` i, alertdagi `device.hostname` va incidentdagi `affected_asset_uids` uchun bir xil:

1. Boshidagi va oxiridagi bo'sh joylar olib tashlanadi.
2. Kichik harfga o'giriladi.
3. FQDN bo'lsa, birinchi nuqtagacha bo'lgan qism olinadi: `WEB01.corp.local` → `web01`.
4. IP manzil hostname sifatida yozilmaydi.

**Hostname SOAR ning qayerida turadi:**

| SOAR | Ta'sirlangan aktiv qayerda | Hostname qayerdan olinadi |
|---|---|---|
| TheHive | Observable | `dataType: hostname` |
| Cortex XSOAR | Incident field / indicator | `Hostname`, `Device Name` |
| Microsoft Sentinel | Entity `Host` | `HostName` (`DnsDomain` qo'shilmaydi) |
| Splunk SOAR | Artifact (CEF) | `destinationHostName`, `deviceHostname` |
| IBM QRadar SOAR | Artifact | `System Name` |
| FortiSOAR | Assets moduli yozuvi | `hostname` maydoni |

Agar SOAR da aktivning faqat IP manzili bo'lsa, u `affected_asset_uids` ga yozilmaydi — bog'lanish `alerts[]` orqali tiklanadi.

> **UzCORE tomonidagi himoya.** UzCORE kelgan qiymatni ikki joydan qidiradi: aktivning `asset_uid` i va normallashtirilgan `technical.hostname`. Bundan tashqari, `affected_asset_uids` bo'sh bo'lsa yoki mos kelmasa, aktiv `alerts[]` → alertdagi `device.hostname` orqali topiladi. Shuning uchun `alerts[]` ga hodisaga tegishli SIEM alert ID larini yozish muhim.

**`indicators[]` elementi:**

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `type` | enum | **R\*** | `ipv4` │ `ipv6` │ `domain` │ `url` │ `md5` │ `sha1` │ `sha256` │ `email` │ `file_name` │ `user_agent` │ `registry_key` |
| `value` | string | **R\*** | Indikator qiymati. Refang qilinadi, domen va hash kichik harfda yoziladi, RFC 1918 ichki manzillar yuborilmaydi. |

> Indikator faqat ikki maydondan iborat: **turi va qiymati**. `role`, `tlp` va `first_seen` ataylab yo'q — birinchisi hech bir SOAR da mavjud emas va bo'sh kelardi, ikkinchisi hodisaning `tlp` si bilan qoplangan, uchinchisi esa `lifecycle.detected_at` ni takrorlaydi.

**`mitre_attacks[]` — uch darajali struktura:**

```
mitre_attacks[]
 └── tactic                    (bitta taktika, majburiy)
 └── techniques[]              (shu taktika ostidagi texnikalar, kamida bitta)
      └── sub_techniques[]     (shu texnika ostidagi subtexnikalar, ixtiyoriy)
```

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `tactic` | object | **R\*** | Taktika. **Majburiy** — taktikasiz texnika yuborilmaydi. |
| `tactic.uid` | string | **R\* · STD** | Format: `TA####`. Misol: `"TA0006"`. To'liq ro'yxat: **Ilova B.9** |
| `tactic.name` | string | **O** | `"Credential Access"` |
| `techniques` | array | **R\*** | Shu taktika ostidagi texnikalar. **Kamida bitta**, bo'sh massiv rad etiladi. |
| `techniques[].uid` | string | **R\* · STD** | Format: `T####`. Misol: `"T1110"`. Subtexnika bu yerga yozilmaydi. |
| `techniques[].name` | string | **O** | `"Brute Force"` |
| `techniques[].sub_techniques` | array | **O** | Subtexnikalar. Bo'lmasa maydon umuman yozilmaydi. |
| `…sub_techniques[].uid` | string | **R\* · STD** | Format: `T####.###`. Misol: `"T1110.001"` |
| `…sub_techniques[].name` | string | **O** | `"Password Guessing"` |

**Majburiy qoidalar:**

- **Bitta taktika bir marta uchraydi.** Bir taktika ostida bir nechta texnika bo'lsa, ular `techniques[]` ichida sanaladi — taktika takrorlanmaydi.
- **Subtexnika ota-texnikasiz yuborilmaydi.** Agar manba tizim faqat `T1110.001` bersa, konnektor yoki API orqali to'g'ridan-to'g'ri yuboruvchi dasturchi ota-texnikani ID ning o'zidan chiqaradi (`T1110`) va uni `techniques[].uid` ga yozadi, subtexnikani esa uning `sub_techniques[]` iga joylaydi.
- **Taktika majburiy.** Manba tizimda taktika bo'lmasa, uni ATT&CK katalogidan aniqlash kerak. Bitta texnika bir nechta taktikaga tegishli bo'lsa, analitik hodisada qaysi maqsadda ishlatilganini tanlaydi.
- **Takrorlanish taqiqlanadi.** Bir xil `tactic.uid`, bir xil `techniques[].uid` yoki bir xil `sub_techniques[].uid` ikki marta yozilsa, payload rad etiladi.

**Misol — bir taktika ostida uchta texnika, biri ikkita subtexnika bilan:**

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

> **Nega taktika majburiy?** Taktika texnikadan **kelib chiqmaydi** — bitta texnika bir nechta taktikaga tegishli bo'lishi mumkin. Masalan `T1078 Valid Accounts` to'rtta taktikada uchraydi: Initial Access, Persistence, Privilege Escalation, Defense Evasion. Faqat texnika ID si yuborilsa, hujumchi kirayotgan edimi, o'rnashayotgan edimi yoki imtiyoz oshirayotgan edimi — bilib bo'lmaydi.
>
> Shu sababli bitta texnika **bir nechta taktika ostida** uchrashi ham normal: hujumchi `T1078` ni avval kirish uchun, keyin o'rnashish uchun ishlatgan bo'lsa, u `TA0001` va `TA0003` guruhlarining ikkalasida ham yoziladi.

> **Alert bilan farq:** alert telemetriyasida bu ma'lumot OCSF talabi bo'yicha `finding_info.attacks[]` da **tekis** juftliklar shaklida saqlanadi (`{tactic, technique, sub_technique}`). OCSF maydon strukturasini o'zgartirib bo'lmaydi. Incidentda esa ichma-ich shakl ishlatiladi — u analitik yozgan to'liq rasmni aniqroq ifodalaydi. Konnektor ikkala shaklni ham yasaydi.

> **`kill_chain_phase` yo'q.** Lockheed Martin kill-chain maydoni bu hujjatda **umuman ishlatilmaydi** — na incidentda, na alertda. ATT&CK taktikalari xuddi shu savolga aniqroq javob beradi (7 bosqich o'rniga 14 taktika), va ikkala maydonni birga saqlash ziddiyatga olib keladi — masalan `kill_chain_phase: "delivery"` yonida `tactic: TA0040 Impact`. Hujum bosqichi `mitre_attacks[].tactic` orqali ifodalanadi. Taktikalarning to'liq ro'yxati: **Ilova B.9**.
>
### 2.4.8 `response` — nima qilindi

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `actions_taken` | array[string] | **O** | Case doirasida bajarilgan harakatlar, erkin matn. Har biri ≤300 belgi. |
| `containment_status` | enum | **O · STD** | Javob bosqichi: `not_contained` │ `partially_contained` │ `contained` │ `eradicated` │ `recovered` |
| `closing_note` | string | **O** | Case yopilishidagi erkin izoh, ≤2000 belgi. |

> **`actions_taken` va `closing_note` ga maxfiy ma'lumot yozilmaydi.** Xost nomi, IP manzil, foydalanuvchi login i, xodim ismi, buyruq qatori — hech biri. To'g'ri: `"Zararlangan xost izolyatsiya qilindi"`. Noto'g'ri: `"web014 (10.0.2.14) izolyatsiya qilindi, root hisobi bloklandi"`.

**`containment_status` — NIST SP 800-61 javob bosqichlari:**

| Qiymat | Ma'nosi |
|---|---|
| `not_contained` | Lokalizatsiya qilinmagan, hujum davom etmoqda |
| `partially_contained` | Qisman lokalizatsiya qilingan, ba'zi yo'nalishlar ochiq |
| `contained` | Lokalizatsiya qilingan, tarqalish to'xtatilgan |
| `eradicated` | Zararli komponent tizimdan olib tashlangan |
| `recovered` | Tizim normal ishga qaytgan |

Bu maydon `lifecycle.status_id` bilan **takrorlanmaydi**: `status_id` ish jarayonini bildiradi (kim ishlayapti), `containment_status` esa texnik holatni (hujum to'xtatildimi). `status_id: 2` (In Progress) bo'lgan hodisa lokalizatsiya qilingan ham, qilinmagan ham bo'lishi mumkin — va operator uchun eng shoshilinch ko'rinish aynan shu ikkisining kesishmasi: **kritik + lokalizatsiya qilinmagan**.

**`closing_note` — yopish sababi emas.** Yopish sababi `lifecycle.verdict_id` da strukturali shaklda yoziladi (Ilova B.6). `closing_note` esa uning yonidagi erkin izoh: nima qilingani, nima aniqlangani.

### 2.4.9 `activity` — case xronologiyasi

Case ustida bajarilgan barcha qadamlar vaqt tartibida: ochilishi, holat o'zgarishlari, izohlar, vazifalar, yopilishi va qayta ochilishi. Bu ma'lumot hodisa qanday yuritilganini ko'rsatadi — milliy operator og'ir hodisani ko'rib chiqayotganda tashkilot nima qilganini shu orqali biladi.

> **Vazifalar ro'yxati alohida yuborilmaydi.** Case ichidagi tasklarning to'liq ro'yxati (sarlavha, mas'ul, holat) UzCORE ga uzatilmaydi. Xronologiyada esa `task_created` va `task_completed` voqealari saqlanadi — ya'ni vazifa qo'yilgani va bajarilgani **fakti va vaqti** ko'rinadi, mazmuni esa ko'rinmaydi. Bu javob sur'atini o'lchash uchun yetarli va maxfiylik xavfini keltirmaydi.

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `time` | timestamp | **R\*** | Voqea vaqti (ISO 8601 UTC) |
| `type` | enum | **R\*** | Voqea turi — quyidagi jadval |
| `to_status_id` | integer | **C** | Yangi holat. **`type` = `status_changed` bo'lganda majburiy.** |
| `to_severity_id` | integer | **C** | Yangi xavflilik. **`type` = `severity_changed` bo'lganda majburiy.** |

**`type` qiymatlari:**

| Qiymat | Qachon yoziladi | Qo'shimcha maydon |
|---|---|---|
| `case_opened` | Case ochildi | — |
| `case_closed` | Case yopildi | — |
| `case_reopened` | Yopilgan case qayta ochildi | — |
| `status_changed` | Holat o'zgardi | `to_status_id` |
| `comment_added` | Izoh yozildi | — |
| `task_created` | Vazifa qo'yildi | — |
| `task_completed` | Vazifa bajarildi | — |
| `severity_changed` | Xavflilik qayta baholandi | `to_severity_id` |
| `artifact_added` | Yangi IOC yoki dalil qo'shildi | — |
| `other` | Yuqoridagilarga to'g'ri kelmaydi | — |

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

> ## Izoh matni YUBORILMAYDI
>
> `comment_added` faqat **izoh yozilgani faktini va vaqtini** bildiradi — matnning o'zi emas.

**To'liq tarix yuboriladi.** Har yangilanishda butun xronologiya qayta yuboriladi, faqat yangi yozuvlar emas.

**Manba tizimlarda qayerdan olinadi:**

| Tizim | Manba |
|---|---|
| TheHive | `Case Logs`, `Task Logs`, audit trail |
| Cortex XSOAR | `War Room` yozuvlari, `Incident Audit Trail` |
| Microsoft Sentinel | `Comments` + `SecurityIncident` jadvalidagi holat o'zgarishlari |
| Splunk SOAR | Container audit, `Notes` |
| IBM QRadar SOAR | Incident timeline |
| ServiceNow SIR | `Activity Stream`, `Work Notes` |
| Updive | Case activity oqimi |

> **`case_reopened` alohida ahamiyatga ega.** Yopilgan hodisaning qayta ochilishi — hodisa yaxshi hal qilinmaganini bildiradi. Bu milliy darajada ko'rinadigan sifat signali va `status_id` ning o'zi buni ko'rsatmaydi: u shunchaki `5` dan `2` ga qaytadi va tarixsiz bu bilinmaydi.

## 2.5 Minimal misol — eng kam maydon bilan

Agar tashkilotda to'liq ma'lumot bo'lmasa, quyidagi payload qabul qilinadi:

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

## 2.6 Yopish misoli

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

## 2.7 Tez-tez uchraydigan xatolar

| Xato | Oqibati | To'g'ri yechim |
|---|---|---|
| Har yangilanishda yangi `report_id` | Bitta hodisa milliy statistikada 5 ta bo'lib ko'rinadi | §1.5 formulasidan foydalanish |
| `event_type` kategoriyaga mos emas | `422` xatolik | Ilova A jadvalidan tekshirish |
| `org_id` incident elementi ichida | `422` xatolik — u konvertga tegishli | Konvertda bir marta |
| `related_report_ids` ichida o'z `report_id` si | `422` xatolik | Bu maydon faqat BOSHQA hodisalarga havola qiladi |
| Bitta so'rovda bir nechta tashkilot | `422` xatolik | Har bir `org_id` uchun alohida so'rov |
| Manba tizim holati to'g'ridan-to'g'ri yuborilgan (`"Active"`, `"Done"`) | `422` xatolik | Ilova B.5 mapping jadvali orqali `status_id` ga o'girish |
| `status_id` ga `contained` mazmuni berilgan | Ish jarayoni va javob bosqichi aralashadi | Lokalizatsiya `containment_status` da ifodalanadi |
| `detected_at` = `opened_at` | Aniqlash-javob oralig'i 0 bo'lib ko'rinadi, MTTA ko'rsatkichi buziladi | Vositaning haqiqiy aniqlash vaqtini olish |
| Aktivlar ma'lum bo'lsa ham `affected_asset_uids` bo'sh | Hodisa hech qanday aktivga bog'lanmaydi, korrelyatsiyaning katta qismi yo'qoladi | Aktivlar ma'lum bo'lganda to'ldiriladi. Hech qanday ichki aktiv ishtirok etmagan yoki ko'lam hali aniqlanmagan bo'lsa, `[]` yuboriladi va keyingi lifecycle yangilanishida to'ldiriladi. |
| `indicators` ga ichki IP lar kiritilgan | Boshqa tashkilotlar bilan soxta mos kelish, noto'g'ri "kampaniya" signali | RFC 1918 manzillarni filtrlash |
| `description` ga xom log yozish | Maxfiy ma'lumot chiqib ketishi | Faqat tozalangan xulosa yozish |
| `actions_taken` yoki `closing_note` ga xost nomi/IP yozish | TLP:RED ma'lumot AMBER hodisaga sizib kiradi | Umumiy ifoda: "Zararlangan xost izolyatsiya qilindi" |
| `activity` da izoh matni yuborilgan | `422` xatolik — sxemada bunday maydon yo'q | Faqat `time` va `type` yuboriladi |
| `activity` da faqat oxirgi yangi yozuvlar | Xronologiya uzilib qoladi | Har yangilanishda to'liq tarix |
| `status_id` ga `0` yoki `99` yuborilgan | `422` xatolik | Faqat `1`–`5`; Ilova B.5 dan eng yaqin mosini tanlash |
| Mahalliy vaqt (`+05:00` siz) | Barcha trend grafiklar 5 soatga siljiydi | UTC ga o'girish, `Z` qo'shish |

---

# 3. Alert — OCSF Detection Finding

## 3.1 Ta'rif va incidentdan farqi

Alert — **bitta xavfsizlik vositasi yaratgan bitta aniqlash**. U OCSF 1.9.0 standartining **Detection Finding** klassida (`class_uid = 2004`, `category_uid = 2 Findings`) ifodalanadi.


**Muhim:** alertda `activity_id` **har doim `1` (Create)**. Alert — o'zgarmas aniqlash faktı. Uning holati o'zgarsa (yopildi, false positive deb topildi) — bu incident telemetriyasida ifodalanadi, alertda emas. Aks holda konnektor har siklda butun alert bazasini qayta skanerlashi kerak bo'lardi.

## 3.2 Yuborish formati — konvert

So'rov tanasi — **konvert (envelope)**: tashkilot identifikatsiyasi yuqorida bir marta, alertlar esa `alerts[]` massivida.

```json
{
  "telemetry_type": "alert_batch",
  "schema_version": "1.0",
  "org_id": "b3f1c2a4-1d2e-4f56-9abc-1234567890ab",
  "collected_at": "2026-08-13T04:15:00Z",
  "alerts": [ /* OCSF Detection Finding obyektlari */ ]
}
```

| Maydon | Tur | R/O | Ta'rif |
|---|---|---|---|
| `telemetry_type` | string | **R** | Qat'iy qiymat: `"alert_batch"` |
| `schema_version` | string | **R** | `"1.0"` |
| `org_id` | UUID | **R** | Alertlar tegishli tashkilot — **ma'lumot egasi** (§1.3). Bitta so'rovda bitta tashkilot. |
| `collected_at` | timestamp | **R** | To'plam integratsiya tomonidan yig'ilgan vaqt. **ISO 8601 UTC.** |
| `alerts` | array | **R** | 1–500 ta OCSF Detection Finding obyekti |

- Bitta so'rovda **bitta `org_id`**. MSSP har bir mijoz uchun alohida so'rov yuboradi.
- Bitta alertni yuborish uchun ham konvert ishlatiladi: `"alerts": [ { ... } ]`.
- Alert elementlarining **ichida `org_id` yoki `collected_at` bo'lmaydi** — ular konvertda.

> `collected_at` (ISO 8601) va alert ichidagi `time` (epoch ms) ikkalasi ham bo'ladi va bu **xato emas**: `time` — vosita aniqlagan vaqt, `collected_at` — integratsiya uni olgan vaqt. Farqi yetkazib berish kechikishini ko'rsatadi.

## 3.3 To'liq JSON misol — bitta alert

Quyida `alerts[]` massivining bitta elementi to'liq ko'rsatilgan (konvert §3.2 da):

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
    "event_name": "sshd: brute force trying to get access to the system",
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

## 3.4 Maydonlar

### 3.4.1 OCSF klassifikatsiyasi — qat'iy (const) qiymatlar

Bu to'rt maydon **har doim bir xil**. Boshqa qiymat yuborilsa payload rad etiladi.

| Maydon | Tur | R/O | Qiymat | Nima uchun |
|---|---|---|---|---|
| `class_uid` | integer | **R · STD** | `2004` | OCSF Detection Finding klassi |
| `category_uid` | integer | **R · STD** | `2` | OCSF Findings toifasi |
| `activity_id` | integer | **R · STD** | `1` | Create. Alert o'zgarmas — boshqa qiymat yo'q |
| `type_uid` | integer | **R · STD** | `200401` | `class_uid × 100 + activity_id` |

**OCSF dagi matnli nomlari — ma'lumot uchun, yuborilmaydi:**

| Maydon | Qiymat | OCSF matni |
|---|---|---|
| `class_uid` | `2004` | Detection Finding |
| `category_uid` | `2` | Findings |
| `activity_id` | `1` | Create |
| `type_uid` | `200401` | Detection Finding: Create |

### 3.4.2 Vaqt maydonlari — hammasi epoch millisekund

| Maydon | Tur | R/O | Ta'rif |
|---|---|---|---|
| `time` | integer | **R** | Aniqlash ishga tushgan vaqt, **epoch ms**. |
| `start_time` | integer | **O** | Kuzatilgan faoliyat boshlangan vaqt. |
| `end_time` | integer | **O** | Kuzatilgan faoliyat tugagan vaqt. |

> **`start_time` va `end_time` juftlik.** `end_time` yuborilsa, `start_time` ham majburiy va `start_time ≤ end_time` bo'lishi shart. Aks holda `422`. Jamlangan aniqlashlarda (masalan 10 daqiqada 500 urinish) bu oyna `count` bilan birga hujum intensivligini ko'rsatadi.

### 3.4.3 Xavflilik, holat, jamlanish

| Maydon | Tur | R/O | Ruxsat etilgan qiymatlar |
|---|---|---|---|
| `severity_id` | integer | **R · STD** | `0` Unknown · `1` Informational · `2` Low · `3` Medium · `4` High · `5` Critical · `99` Other |
| `status_id` | integer | **O · STD** | Alertning triaj holati: `0` Unknown · `1` New · `2` In Progress · `3` Suppressed · `4` Resolved · `5` Archived · `99` Other. Mapping: **Ilova B.2**. |
| `count` | integer | **O** | Manba shu bitta aniqlashga jamlagan hodisalar soni (masalan Wazuh `rule.firedtimes`) |

> **`severity_id` diapazon EMAS.** Faqat `{0, 1, 2, 3, 4, 5, 99}` qabul qilinadi. `7`, `50`, `12` — noto'g'ri.
> **`severity_id = 0`** manba tizim xavflilik darajasi bermagan holatda **halol** ishlatiladi. Uni o'ylab topmang.

> **`status_id` va alertni yangilash.** Alert holati o'zgarganda (masalan `Suppressed` bo'lganda) uni **bir xil** `finding_info.uid` bilan qayta yuborish mumkin — yozuv ustiga yoziladi. Idempotentlik kaliti: `org_id` + `metadata.product.name` + `finding_info.uid`. Wazuh kabi holatsiz tizimlarda bu maydon bo'sh qoladi.

**Manba tizimlardan `severity_id` ga mapping:**

| Manba qiymati | `severity_id` |
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

> **Suricata va Snort da tartib teskari:** `1` eng yuqori xavf, `4` eng past. To'g'ridan-to'g'ri ko'chirilsa, kritik alertlar `Low` bo'lib ketadi.

**Faqat raqamli baho beradigan tizimlar uchun (0–100 shkalasi):**

| Oraliq | `severity_id` |
|---|---|
| 0–19 | `1` Informational |
| 20–39 | `2` Low |
| 40–59 | `3` Medium |
| 60–79 | `4` High |
| 80–100 | `5` Critical |

### 3.4.4 `metadata` — manba tizim haqida

| Maydon | Tur | R/O | Ta'rif |
|---|---|---|---|
| `metadata.version` | string | **R · STD** | Qat'iy: `"1.9.0"` — OCSF sxema versiyasi |
| `metadata.product.name` | string | **R** | Vosita nomi: `"Wazuh"`, `"CrowdStrike Falcon"`, `"Microsoft Defender"` |
| `metadata.product.version` | string | **O** | Vosita versiyasi |
| `metadata.event_code` | string | **O** | Ishga tushgan qoida/imzo ID si (Wazuh `rule.id`, Sigma rule id) |
| `metadata.event_name` | string | **O** | `event_code` juftligi — ishga tushgan qoida/imzoning nomi (Wazuh `rule.description`, Suricata signature), ≤300 belgi. UzCORE kengaytmasi: OCSF `metadata` da bu atribut yo'q. |
| `metadata.logged_time` | integer | **O** | Log tizimga tushgan vaqt (epoch ms) |


### 3.4.5 `finding_info` — aniqlashning o'zi

| Maydon | Tur | R/O | Ta'rif |
|---|---|---|---|
| `finding_info.uid` | string | **R** | **Manba vositaning shu aniqlash uchun o'z ID si.** Barqaror bo'lishi shart — idempotentlik kaliti va incidentdagi `alerts[]` bilan bog'lanish nuqtasi. |
| `finding_info.title` | string | **R** | **Qoidaning nomi**, ≤300 belgi. Hodisa matni EMAS: `"SSH brute-force detected"` — to'g'ri, `"Failed login for user admin from 10.0.2.14"` — noto'g'ri (qiymatlar `observables` ga tegishli). |
| `finding_info.attacks[]` | array | **O · STD** | MITRE ATT&CK. Har bir elementda `technique`, `sub_technique` yoki `tactic` dan **kamida bittasi** bo'lishi shart. |

**`attacks[]` elementi:**

```json
{
  "technique":     { "uid": "T1110" },
  "sub_technique": { "uid": "T1110.001" },
  "tactic":        { "uid": "TA0006" }
}
```

`uid` qiymatlari **MITRE katalogidan** olinadi: texnika `T####`, subtexnika `T####.###`, taktika `TA####`. Nom yozilmaydi — faqat ID.

**Manba tizim faqat nom bersa** (masalan Wazuh `rule.mitre.tactic` = `"Credential Access"`), dasturchi nomdan ID ni topib yuboradi: taktikalar to'liq ro'yxati **Ilova B.9** da, texnikalar `https://attack.mitre.org/` da.

### 3.4.6 `device` — ta'sirlangan qurilma

| Maydon | Tur | R/O | Ta'rif |
|---|---|---|---|
| `device.hostname` | string | **R** | **Aktivlar inventarizatsiyasi bilan bog'lovchi kalit.** Normallashtirilgan holda `assets[].asset_uid` ga teng bo'lishi shart (qoida: §2.4.7). |
| `device.ip` | string | **O** | IP manzil |
| `device.mac` | string | **O** | MAC manzil, **kichik harfda**: `00:1a:2b:3c:4d:5e`. Aktivdagi `technical.mac_addresses[]` bilan solishtiriladi. |

### 3.4.7 `observables` — indikatorlar

| Maydon | Tur | R/O | Ta'rif |
|---|---|---|---|
| `observables[].type_id` | integer | **R\* · STD** | Quyidagi jadval |
| `observables[].value` | string | **R\*** | Qiymat. Tashqi qiymatlar refang qilinadi, domen va hash kichik harfda yoziladi. |

> **Ichki qiymatlar ham yuboriladi.** `indicators[]` (incident) dan farqli o'laroq, `observables[]` ga alertda uchragan **barcha** qiymatlar tushadi — jabrlanuvchi xost nomi va ichki IP ham. Sabab: ular aktivga bog'lash uchun kerak, ya'ni "shu aktivdagi alertlar" ro'yxatini shakllantiradi. Tashkilotlararo kampaniya izlashda esa UzCORE faqat tashqi qiymatlarni hisobga oladi.

**Ruxsat etilgan `type_id` qiymatlari:**

| ID | Nomi | Misol |
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


### 3.4.8 `vulnerabilities` — zaifliklar

| Maydon | Tur | R/O | Ta'rif |
|---|---|---|---|
| `vulnerabilities[].cve.uid` | string | **R\* · STD** | CVE identifikatori, `CVE-YYYY-NNNN+` formatida |
| `vulnerabilities[].severity` | string | **O** | Zaiflik xavfliligi manba tizim ko'rsatgan shaklda: `"Critical"`, `"High"`, `"Medium"`, `"Low"` |

## 3.5 Minimal alert misoli

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


## 3.6 Tez-tez uchraydigan xatolar

| Xato | Oqibati | To'g'ri yechim |
|---|---|---|
| `os.type_id: 201` Linux uchun | Butun Linux parki Android bo'lib ko'rinadi | Linux = `200` |
| `time` sekundda yuborilgan | Sana 1970-yilga tushib qoladi | Millisekund: `× 1000` |
| `severity_id: 12` | `422` xatolik | Faqat `{0,1,2,3,4,5,99}` |
| `org_id` alert elementi ichida | `422` xatolik — u konvertga tegishli | Konvertda bir marta |
| So'rov tanasi massiv (`[...]`) | `400` xatolik | Konvert obyekti: `{ "alerts": [...] }` |

---

# 4. Asset Inventory — aktivlar inventarizatsiyasi

## 4.1 Ta'rif va maxfiylik

Tashkilot aktivlarining ro'yxati. Aktivlar ikki guruhga bo'linadi:

| Guruh | Klasslar | Odatiy manba |
|---|---|---|
| **Texnik aktivlar** | `hardware`, `software`, `network`, `service`, `information_resource`, `security_tool` | SIEM / EDR / zaiflik skaneri — avtomatik |
| **Registr aktivlari** | `information`, `process`, `personnel`, `site`, `organization`, `intangible` | Tashkilot tomonidan qo'lda yoki CMDB/GRC tizimidan (O'zMSt 816:2025 L ilovasi bo'yicha yuritiladigan axborot aktivlari reyestri) |

Taksonomiya — 12 ta klass va 70 ta tur — **O'zMSt 816:2025** (§7.9.2 himoya obyektlari) asosida tuzilgan va O'zMSt ISO/IEC 27005:2024, ISO/IEC 27001:2022 Annex A hamda ПҚ-167 bilan kengaytirilgan (to'liq ro'yxat: **Ilova E**). Qaysi klasslarni yuborishni tashkilot o'zi hal qiladi: yuborilgani qabul qilinadi.

> ## ⚠️ MAXFIYLIK — TLP:RED
>
> Bu telemetriya **hostname, IP manzil, ochiq portlar va zaifliklarni** o'z ichiga oladi.
>
> **Tashkilot tomonidagi majburiy choralar:** faqat TLS 1.2+ orqali yuborish, `tlp` maydonida faqat `RED`.
>
> `personnel` klassida **ism, login, email, telefon hech qayerda yozilmaydi**, shu jumladan `asset_uid` da ham. `asset_uid` anonim bo'ladi: `role-ciso`, `user-0417`.

## 4.2 Yuborish rejimi — upsert

UzCORE aktivlarni **upsert** tamoyilida qabul qiladi: kelgan aktiv bazaga yoziladi yoki mavjud yozuv yangilanadi. Yuborilmagan aktiv **o'chirilmaydi** — u bazada qoladi, faqat uning `last_seen` qiymati yangilanmaydi.

Shu sababli texnik va registr aktivlarini **alohida, har xil ritmda** yuborish mumkin: SIEM har kuni texnik aktivlarni yuboradi, qo'lda kiritilgan registr esa o'zgarganda yuboriladi. Ular bir-biriga xalaqit bermaydi.

| Qoida | Tafsilot |
|---|---|
| **Interval** | Texnik aktivlar — kuniga bir marta (tavsiya: tunda). Registr aktivlari — o'zgarganda. |
| **Aktivni o'chirish** | Faqat aniq signal bilan: `lifecycle_status: "decommissioned"` yuboriladi. Ro'yxatda yo'qligi hech narsani anglatmaydi. |
| **Eskirgan aktiv** | `last_seen` uzoq vaqt yangilanmagan aktiv "eskirgan" deb belgilanadi — **faqat `provenance: "discovered"`** aktivlar uchun. Qo'lda kiritilgan (`declared`) aktivlar kamdan-kam yuboriladi, ularga bu qoida qo'llanmaydi. |
| **Idempotentlik** | Upsert tufayli bir xil snapshotni qayta yuborish takroriy yozuv yaratmaydi — aktiv `org_id` + `asset_uid` bo'yicha aniqlanadi. |

## 4.3 To'liq JSON misol

Bitta texnik aktiv (SIEM dan) va bitta registr aktivi (qo'lda kiritilgan):

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

## 4.4 Maydonlar

### 4.4.1 Konvert

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `telemetry_type` | string | **R** | Qat'iy: `"asset_inventory"` |
| `schema_version` | string | **R** | `"1.0"` |
| `org_id` | UUID | **R** | Aktivlar tegishli tashkilot — ma'lumot egasi (§1.3) |
| `tlp` | enum | **R** | Har doim `"RED"`. Boshqa qiymat rad etiladi. |
| `source_system` | string | **O** | Ma'lumotni bergan vosita: `"Wazuh"`, `"Splunk"`, `"Tenable"`, `"CMDB"` |
| `collected_at` | timestamp | **R** | Ma'lumot olingan vaqt (ISO 8601 UTC) |
| `summary` | object | **R** | Tez ko'rsatkichlar (§4.4.2) |
| `assets` | array | **R** | Aktivlar ro'yxati |

### 4.4.2 `summary` — tez ko'rsatkichlar

Bu bloklar dashboardda darhol ko'rsatiladi va `assets[]` massivini to'liq o'qimasdan hisoblanadi.

| Maydon | Tur | R/O | Ta'rif |
|---|---|---|---|
| `summary.total_assets` | integer | **R** | Umumiy qurilmalar soni. **Barcha normallashtirilgan ko'rsatkichlarning maxraji** — masalan "100 aktivga necha hodisa". |
| `summary.servers` | integer | **O** | Serverlar soni |
| `summary.endpoints` | integer | **O** | Ish stansiyalari va noutbuklar soni |
| `summary.network_devices` | integer | **O** | Marshrutizator, kommutator, firewall soni |
| `summary.ot_ics_devices` | integer | **O** | Operatsion texnologiya / sanoat boshqaruv qurilmalari |
| `summary.internet_facing` | integer | **O** | Internetdan ko'rinadigan aktivlar — **milliy hujum yuzasining asosiy raqami** |
| `summary.end_of_life` | integer | **O** | Qo'llab-quvvatlanmaydigan dasturiy/apparat ta'minot |

### 4.4.3 `assets[]` — tuzilishi

Har bir aktiv ikki qismdan iborat: **umumiy yadro** (barcha klasslar uchun bir xil) va **klassga mos bitta obyekt**.

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

**Qoida:** har bir aktivda **faqat o'z klassiga mos obyekt** bo'lishi mumkin. Masalan `personnel` aktivida `technical` obyekti bo'lsa, payload rad etiladi — xodimda IP manzil yoki ochiq port bo'lmaydi.

### 4.4.4 Umumiy yadro — barcha klasslar uchun

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `asset_uid` | string | **R\*** | **Barqaror unikal ID — asosiy bog'lovchi kalit.** Incident `affected_asset_uids` va alert `device.hostname` bilan bir xil yozilishi shart. Snapshotlar orasida o'zgarmaydi. |
| `asset_class` | enum | **R\* · STD** | 12 ta klassdan biri: `information` │ `process` │ `hardware` │ `software` │ `network` │ `service` │ `information_resource` │ `security_tool` │ `personnel` │ `site` │ `organization` │ `intangible` |
| `asset_type` | enum | **R\* · STD** | 70 ta turdan biri. **Tanlangan klassga mos bo'lishi shart.** To'liq ro'yxat: **Ilova E** |
| `criticality` | enum | **O** | `crown_jewel` │ `high` │ `medium` │ `low` |
| `lifecycle_status` | enum | **O** | `active` │ `decommissioned` │ `end_of_life`. Aktivni o'chirishning yagona yo'li — `decommissioned` (§4.2). |
| `provenance` | enum | **O** | `discovered` — vosita topgan (dalil) │ `declared` — qo'lda kiritilgan (da'vo) |
| `first_seen` | timestamp | **O** | Birinchi kuzatilgan vaqt. Boshqarilmaydigan (shadow IT) o'sishni ko'rsatadi. |
| `last_seen` | timestamp | **O** | Oxirgi kuzatilgan vaqt. Eskirganlik qoidasi faqat `discovered` aktivlarga qo'llanadi. |
| `related_asset_uids` | array[string] | **O** | Bog'liq aktivlarning `asset_uid` lari. Quyidagi misollarga qarang. |

> **`personnel` klassida `asset_uid` anonim bo'ladi.** Ism, login, email, telefon yozilmaydi: `role-ciso`, `role-soc-lead`, `user-0417`. Hodisa paytida bog'lanish uchun kontaktlar telemetriyaga emas, tashkilotni ro'yxatdan o'tkazish ma'lumotlariga tegishli.

**`related_asset_uids` — aktivlar orasidagi bog'lanish:**

| Aktiv | `related_asset_uids` | Ma'nosi |
|---|---|---|
| `information_resource/web_resource` | `["web014"]` | Veb-resurs shu serverda ishlaydi |
| `information/processed_data` | `["db02"]` | Ma'lumot shu bazada saqlanadi |
| `process/business_process` | `["app-payments", "db02"]` | Jarayon shu ilova va bazaga bog'liq |
| `personnel/responsible_person` | `["web014", "db02"]` | Mas'ul shaxs shu aktivlar uchun javobgar |
| `organization/supplier` | `["fw01"]` | Yetkazib beruvchi shu qurilmaga xizmat ko'rsatadi |

Registr aktivlarining milliy qiymati aynan shu bog'lanishda: masalan, "to'lov jarayoni qaysi serverlarga bog'liq" yoki "bu yetkazib beruvchi qaysi tizimlarga kirish huquqiga ega".

### 4.4.5 `technical` — texnik klasslar

`hardware`, `software`, `network`, `service`, `information_resource`, `security_tool` — bu olti klass uchun **majburiy** obyekt. Boshqa klasslarda taqiqlangan.

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `hostname` | string | **O** | To'liq hostname / FQDN (`web014.bank.local`) |
| `manufacturer` | string | **O** | Apparat ishlab chiqaruvchisi: `"Dell"`, `"HP"`, `"Cisco"`. Ta'minot zanjiri zaifligiga javob uchun. |
| `model` | string | **O** | Model: `"PowerEdge R750"` |
| `os.type_id` | integer | **O · STD** | OCSF enumi, alert bilan bir xil: `0` Unknown · `100` Windows · `101` Windows Mobile · `200` Linux · `201` Android · `300` macOS · `301` iOS · `302` iPadOS · `400` Solaris · `401` AIX · `402` HP-UX · `99` Other (Ilova B.4) |
| `os.name` | string | **O** | `"Ubuntu Server"`, `"Windows Server"` |
| `os.version` | string | **O** | `"22.04"`, `"2022"` |
| `os.build` | string | **O** | Build / yamoq darajasi: `"5.15.0-101"`, `"20348.2402"` |
| `ip_addresses[].value` | string | **R\*** | IP manzil |
| `ip_addresses[].type` | enum | **O** | `ipv4` │ `ipv6` |
| `ip_addresses[].scope` | enum | **R\*** | `internal` │ `public` │ `dmz` |
| `mac_addresses` | array[string] | **O** | MAC manzillar, kichik harfda, ikki nuqtali formatda: `["00:1a:2b:3c:4d:5e"]`. Alertdagi `device.mac` bilan solishtirish uchun — `hostname` mos kelmaganda zaxira bog'lanish yo'li. |
| `open_ports` | array[integer] | **O** | Ochiq portlar: `[22, 80, 443]`, 0–65535 |
| `as_protection_class` | enum | **O · STD** | Avtomatlashtirilgan tizimning ruxsatsiz foydalanishdan himoyalanganlik sinfi (**O'z DSt 2814:2014**; O'zMSt 816:2025 §7.9.4): `3B` │ `3A` │ `2B` │ `2A` │ `1D` │ `1G` │ `1V` │ `1B` │ `1A`. **Faqat `information_system` va `industrial_control_system` turlarida** — boshqa turlarda rad etiladi |
| `exposure` | enum | **R\*** | `internet_facing` │ `dmz` │ `internal`. **Eng muhim filtr** — "internetga ochiq aktivlardagi kritik zaifliklar" ko'rinishi shunga tayanadi. |
| `environment` | enum | **O** | `production` │ `staging` │ `development` │ `test` |
| `software_inventory[].product` | string | **R\*** | Mahsulot nomi: `"Apache HTTP Server"` |
| `software_inventory[].version` | string | **O** | O'rnatilgan versiya. Versiyasiz CVE mosligi ishlamaydi. |
| `software_inventory[].cpe` | string | **O · STD** | CPE 2.3: `cpe:2.3:<part>:<vendor>:<product>:<version>:...` — 13 qism, bo'shlari `*`. Manba: `https://nvd.nist.gov/products/cpe` |
| `known_cves[].cve_id` | string | **R\* · STD** | `CVE-YYYY-NNNN+`, katta harflarda. **Milliy erta ogohlantirishning bog'lovchi kaliti.** |
| `known_cves[].status` | enum | **O** | `unpatched` │ `patched` │ `mitigated` │ `accepted_risk` |
| `known_cves[].detected_at` | timestamp | **O** | Zaiflik aniqlangan vaqt |

> **`exposure` va `ip_addresses[].scope` farqi.** Aktiv ichki IP ga ega bo'lib (`scope: internal`), NAT yoki reverse proxy orqali internetdan ochiq bo'lishi mumkin (`exposure: internet_facing`). Shuning uchun ikkalasi ham kerak.

> **`software_inventory` nima uchun kerak, agar `known_cves` bor bo'lsa.** Yangi kritik CVE e'lon qilinganda tashkilotlarning skanerlari hali yangilanmagan bo'ladi. UzCORE esa yangi CVE ma'lumoti va dasturiy ta'minot ro'yxati orqali kim zarar ko'rishi mumkinligini darhol aniqlaydi. `cpe` bu moslikni aniq qiladi.

### 4.4.6 Registr klasslari obyektlari

`information`, `process`, `personnel`, `site`, `organization`, `intangible` klasslari uchun alohida obyektlar. Maydonlar **ISO/IEC 27002:2022** nazorat vositalari va **ISO/IEC 27005:2022** xavf baholash tamoyillari asosida aniqlangan.

Barcha maydonlar **ixtiyoriy**. Bo'sh obyekt (`{}`) ham to'g'ri hisoblanadi — tashkilot qaysi maydonni to'ldirishni o'zi hal qiladi.

---

#### `information` — ma'lumot aktivlari

Asos: **O'zMSt 816:2025 L ilova** (kirish cheklovi, yaxlitlik va mavjudlik toifalari); ISO 27002 **5.33** (yozuvlarni himoya qilish), **5.34** (PII), **8.10** (o'chirish), **8.11** (maskalash), **8.12** (DLP), **8.13** (zaxira), **8.24** (kriptografiya).

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `confidentiality_marks` | array[enum] | **O · STD** | Kirish cheklovi toifalari — quyidagi jadval. **Bir nechtasi birga bo'lishi mumkin**: `["PD","BT"]`. `OD` faqat yolg'iz |
| `integrity_category` | enum | **O · STD** | `V` │ `N` │ `-` — quyidagi jadval |
| `availability_category` | enum | **O · STD** | `B` │ `V` │ `S` │ `N` — quyidagi jadval |
| `data_categories` | array[enum] | **O** | `financial` │ `health` │ `biometric` │ `commercial_secret` │ `operational` │ `technical` │ `telemetry` │ `other` |
| `contains_pii` | boolean | **O** | Shaxsga doir ma'lumot mavjudmi (27002 5.34) |
| `pii_volume_band` | enum | **O** | `none` │ `under_1k` │ `under_100k` │ `under_1m` │ `over_1m`. **Aniq son yozilmaydi.** `contains_pii: false` bo'lsa faqat `none` |
| `storage_location` | enum | **O** | `on_premise` │ `national_cloud` │ `foreign_cloud` │ `hybrid` │ `offline` — ma'lumot rezidentligi (27002 5.23) |
| `retention_days` | integer | **O** | Saqlash muddati, kunlarda. `0` — muddat belgilanmagan (27002 5.33, 8.10) |
| `encryption.at_rest` | boolean | **O** | Saqlashda shifrlanganmi (27002 8.24) |
| `encryption.in_transit` | boolean | **O** | Uzatishda shifrlanganmi |
| `masking_applied` | boolean | **O** | Maskalash / psevdonimlashtirish qo'llanganmi (27002 8.11) |
| `dlp_applied` | boolean | **O** | DLP vositasi qamrab olganmi (27002 8.12) |
| `backup.exists` | boolean | **O** | Zaxira nusxa bormi (27002 8.13) |
| `backup.frequency` | enum | **O** | `continuous` │ `hourly` │ `daily` │ `weekly` │ `monthly` │ `none` |
| `backup.offsite` | boolean | **O** | Zaxira boshqa jismoniy joyda saqlanadimi |
| `backup.last_tested_at` | date | **O** | `YYYY-MM-DD`. Tiklash oxirgi marta sinab ko'rilgan sana |
| `regulatory_scope` | array[enum] | **O** | `pq_167` │ `personal_data_law` │ `state_secret` │ `banking` │ `healthcare` │ `pci_dss` │ `gdpr` │ `other` (27002 5.31, 5.34) |

**O'zMSt 816:2025 L ilovasi bo'yicha toifalar:**

| Maydon | Kod | Ma'nosi |
|---|---|---|
| `confidentiality_marks` | `SS` | Davlat siri — sir tutilgan |
| | `S` | Davlat siri — maxfiy |
| | `DSP` | Xizmatda foydalanish uchun |
| | `KT` | Tijorat siri |
| | `BT` | Bank siri |
| | `PD` | Shaxsga doir ma'lumotlar |
| | `KO` | Tashkilotning konfidensial ma'lumotlari |
| | `OD` | Ochiq ma'lumotlar |
| `integrity_category` | `V` | Yuqori — ruxsatsiz o'zgartirish sezilarli bevosita zarar yetkazadi |
| | `N` | Past — kichik, noaniq zarar |
| | `-` | Yaxlitlikni ta'minlash talab qilinmaydi |
| `availability_category` | `B` | To'siqsiz — uzilish **1 daqiqadan** oshmaydi |
| | `V` | Yuqori — uzilish **1 soatdan** oshmaydi |
| | `S` | O'rtacha — uzilish **12 soatdan** oshmaydi |
| | `N` | Past — uzilish 12 soatdan oshishi mumkin |

**Tur va toifalar mosligi** — sxema tekshiradi:

| `asset_type` | `confidentiality_marks` da bo'lishi shart |
|---|---|
| `state_secret` | `SS` yoki `S` |
| `confidential_data` | `DSP`, `KT`, `BT`, `PD` yoki `KO` dan kamida bittasi |
| `personal_data` | `PD` |
| `public_data` | Faqat `["OD"]` |

`PD` belgisi va `contains_pii` bir-biriga zid bo'lmasligi kerak: `PD` bo'lsa `contains_pii: false` rad etiladi, `contains_pii: true` bo'lsa `PD` bo'lishi shart.

---

#### `process` — biznes-jarayonlar

Asos: ISO 27002 **5.29** (uzilish paytida xavfsizlik), **5.30** (AKT uzluksizligi, BIA), **5.2** (rollar); ISO 27005 **7.3.2**.

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `process_owner_uid` | string | **O** | Jarayon egasining `asset_uid` i — `personnel` klassidagi **anonim** ID. Ism yozilmaydi (27002 5.2) |
| `citizen_facing` | boolean | **O** | Uzilish fuqarolarga bevosita ta'sir qiladimi. **Milliy ustuvorlikni belgilovchi maydon** |
| `availability_category` | enum | **O · STD** | `B` │ `V` │ `S` │ `N` — O'zMSt 816:2025 L ilovasi, `information` dagi bilan bir xil shkala |
| `bia.completed` | boolean | **O** | Biznesga ta'sir tahlili o'tkazilganmi (27002 5.30) |
| `bia.last_review_at` | date | **O** | `YYYY-MM-DD` |
| `bia.rto_minutes` | integer | **O** | **RTO** — tiklanishning maqsadli vaqti, minutlarda |
| `bia.rpo_minutes` | integer | **O** | **RPO** — yo'qotilishi mumkin bo'lgan ma'lumot oynasi, minutlarda |
| `bia.mtpd_minutes` | integer | **O** | **MTPD** — uzilishning chidab bo'ladigan eng uzun muddati |
| `continuity_plan.exists` | boolean | **O** | Uzluksizlik rejasi bormi (27002 5.29, 5.30) |
| `continuity_plan.last_tested_at` | date | **O** | Reja oxirgi marta sinovdan o'tgan sana |
| `continuity_plan.manual_fallback` | boolean | **O** | AT ishlamaganda qo'lda bajarish imkoniyati bormi |
| `impact_if_disrupted` | enum | **O** | `low` │ `medium` │ `high` │ `critical` |
| `regulatory_scope` | array[enum] | **O** | `information` dagi bilan bir xil ro'yxat |

---

#### `personnel` — xodimlar va rollar

Asos: ISO 27002 **5.2** (rollar), **5.3** (vazifalarni ajratish), **6.1** (tekshiruv), **6.2** (shartnoma), **6.3** (o'qitish), **6.6** (NDA), **6.7** (masofadan ishlash), **8.2** (imtiyozli kirish).

> ## ⚠️ SHAXSIY MA'LUMOT TAQIQLANGAN
>
> Bu obyektda **ism, familiya, login, email, telefon, tug'ilgan sana, erkin matnli lavozim nomi yo'q**. Sxema ularni qabul qilmaydi — `additionalProperties: false`.
>
> **Tavsiya:** `represents: "role"` yoki `"group"` ishlatish. Bitta shaxsni ifodalash o'rniga rolni ifodalash anonimlikni kuchaytiradi va ro'yxatni barqaror qiladi.

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `represents` | enum | **O** | `individual` │ `role` │ `group` — yozuv kimni ifodalaydi |
| `headcount` | integer | **O** | Shu rol/guruhdagi odamlar soni. **`represents: "individual"` bo'lsa taqiqlanadi** |
| `role_category` | enum | **O** | `executive` │ `ciso` │ `security_officer` │ `soc_analyst` │ `system_admin` │ `network_admin` │ `dba` │ `developer` │ `ot_engineer` │ `help_desk` │ `auditor` │ `general_user` │ `other` (27002 5.2) |
| `employment_type` | enum | **O** | `employee` │ `contractor` │ `third_party` │ `intern` (27002 6.2, 5.19) |
| `privileged_access` | boolean | **O** | Imtiyozli kirish huquqi bormi (27002 8.2) |
| `privileged_scope` | array[enum] | **O** | `domain_admin` │ `server_admin` │ `database` │ `network` │ `ot_ics` │ `cloud` │ `security_tools` │ `backup` │ `source_code`. **Faqat `privileged_access: true` bo'lganda** |
| `segregation_of_duties_conflict` | boolean | **O** | Vazifalarni ajratish buzilganmi (27002 5.3) |
| `screening_completed` | boolean | **O** | Ishga qabul oldidan tekshiruv o'tkazilganmi (27002 6.1) |
| `nda_signed` | boolean | **O** | Maxfiylik kelishuvi imzolanganmi (27002 6.6) |
| `security_training.completed` | boolean | **O** | Xabardorlik kursi tugatilganmi (27002 6.3) |
| `security_training.last_completed_at` | date | **O** | `YYYY-MM-DD` |
| `remote_access` | boolean | **O** | Masofadan ishlash huquqi bormi (27002 6.7) |
| `access_to_confidentiality_marks` | array[enum] | **O · STD** | Kirish huquqi bo'lgan ma'lumot toifalari — `information.confidentiality_marks` dagi kodlar: `["KO","PD"]` |

---

#### `site` — jismoniy obyektlar

Asos: ISO 27002 **7.1** (perimetr), **7.2** (kirish nazorati), **7.3** (xonalarni himoyalash), **7.4** (jismoniy kuzatuv), **7.5** (tabiiy tahdidlar), **7.11** (qo'llab-quvvatlovchi infratuzilma).

> **ANIQ MANZIL YOZILMAYDI.** Ko'cha, bino raqami va GPS koordinatasi sxemada yo'q. Faqat **hudud kodi** — ISO 3166-2:UZ.

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `site_type` | enum | **O** | `datacenter` │ `colocation` │ `server_room` │ `office` │ `branch` │ `industrial_plant` │ `substation` │ `dr_site` │ `warehouse` │ `remote_facility` |
| `region_code` | enum | **O · STD** | ISO 3166-2:UZ — `UZ-AN` Andijon · `UZ-BU` Buxoro · `UZ-FA` Farg'ona · `UZ-JI` Jizzax · `UZ-NG` Namangan · `UZ-NW` Navoiy · `UZ-QA` Qashqadaryo · `UZ-QR` Qoraqalpog'iston · `UZ-SA` Samarqand · `UZ-SI` Sirdaryo · `UZ-SU` Surxondaryo · `UZ-TK` Toshkent sh. · `UZ-TO` Toshkent vil. · `UZ-XO` Xorazm · `FOREIGN` — mamlakatdan tashqarida |
| `ownership` | enum | **O** | `owned` │ `leased` │ `colocation` │ `third_party` (27002 5.19) |
| `secure_area` | boolean | **O** | Himoyalangan hudud sifatida belgilanganmi (27002 7.1, 7.3, 7.6) |
| `physical_access_control` | array[enum] | **O** | `none` │ `key` │ `badge` │ `pin` │ `biometric` │ `mantrap` │ `guard` │ `visitor_log` (27002 7.2) |
| `physical_monitoring` | array[enum] | **O** | `none` │ `cctv` │ `intruder_alarm` │ `guard_patrol` │ `access_log` │ `environmental_sensor` (27002 7.4) |
| `supporting_utilities` | array[enum] | **O** | `ups` │ `generator` │ `redundant_power` │ `cooling` │ `fire_suppression` │ `water_detection` │ `redundant_telecom` (27002 7.11) |
| `environmental_threats` | array[enum] | **O** | `none` │ `seismic` │ `flood` │ `fire` │ `extreme_heat` │ `dust` │ `power_instability` (27002 7.5) |
| `hosts_critical_assets` | boolean | **O** | Bu obyektda `crown_jewel` yoki `high` aktivlar joylashganmi |

---

#### `organization` — tashqi tashkilotlar va bo'linmalar

Asos: ISO 27002 **5.19** (ta'minotchi munosabatlari), **5.20** (shartnomadagi xavfsizlik shartlari), **5.21** (AKT ta'minot zanjiri), **5.22** (xizmatlarni monitoring va ko'rib chiqish), **5.23** (bulut xizmatlari); ISO 27005 **7.2**.

| Maydon | Tur | R/O | Ta'rif va ruxsat etilgan qiymatlar |
|---|---|---|---|
| `org_role` | enum | **O** | `supplier` │ `ict_supplier` │ `cloud_provider` │ `mssp` │ `subcontractor` │ `internal_unit` │ `partner` │ `regulator` |
| `org_ref` | string | **O** | **Yuridik shaxs** ro'yxat kodi (STIR). Jismoniy shaxs yoki YTT kodi **yozilmaydi** |
| `country_code` | string | **O · STD** | ISO 3166-1 alpha-2, katta harflarda: `UZ`, `RU`, `CN`, `US` (27002 5.21) |
| `access_type` | array[enum] | **O** | `none` │ `physical` │ `remote_logical` │ `privileged` │ `data_processing` │ `source_code` │ `onsite_staff` │ `managed_security` (27002 5.19, 5.20) |
| `agreement.nda` | boolean | **O** | Maxfiylik kelishuvi bormi |
| `agreement.security_clauses` | boolean | **O** | Shartnomada xavfsizlik shartlari bormi (27002 5.20) |
| `agreement.sla` | boolean | **O** | SLA bormi |
| `agreement.right_to_audit` | boolean | **O** | Audit o'tkazish huquqi bormi |
| `agreement.incident_notification` | boolean | **O** | Hodisa haqida xabar berish majburiyati bormi |
| `security_certification` | array[enum] | **O** | `none` │ `iso_27001` │ `iso_22301` │ `pci_dss` │ `soc2` │ `national_cert` │ `other` (27002 5.21, 5.22) |
| `last_review_at` | date | **O** | Oxirgi xavfsizlik ko'rigi sanasi (27002 5.22) |
| `concentration_risk` | boolean | **O** | Bu ta'minotchiga muqobilsiz bog'liqlik bormi (27005 7.2) |

---

#### `intangible` — nomoddiy aktivlar

Asos: O'zMSt 816:2025 §7.9.2 f); O'zMSt ISO/IEC 27005:2024 A.2.2 — asosiy aktiv.

Maydonlari hali aniqlanmagan — hozircha faqat bo'sh obyekt (`{}`) qabul qilinadi. Nomoddiy aktivda IP manzil yoki zaiflik bo'lmaydi; uning ahamiyati boshqa aktivlar bilan bog'lanishda — `related_asset_uids` orqali.

---

#### Misol — beshta registr aktivi

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

**Qaysi klass uchun qaysi maydonlar:**

| Maydon | hardware | software | network | service | information_resource | security_tool | information | process | personnel | site | organization | intangible |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Umumiy yadro | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `technical` | **R** | **R** | **R** | **R** | **R** | **R** | — | — | — | — | — | — |
| `information` | — | — | — | — | — | — | O | — | — | — | — | — |
| `process` | — | — | — | — | — | — | — | O | — | — | — | — |
| `personnel` | — | — | — | — | — | — | — | — | O | — | — | — |
| `site` | — | — | — | — | — | — | — | — | — | O | — | — |
| `organization` | — | — | — | — | — | — | — | — | — | — | O | — |
| `intangible` | — | — | — | — | — | — | — | — | — | — | — | O |

## 4.5 Minimal asset misoli

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

## 4.6 Tez-tez uchraydigan xatolar

| Xato | Oqibati | To'g'ri yechim |
|---|---|---|
| Har snapshotda yangi `asset_uid` | Tarixiy bog'lanish yo'qoladi, har kuni "yangi aktivlar" ko'rinadi | Barqaror ID ishlatish |
| `asset_uid` = IP manzil | IP o'zgarganda aktiv "yo'qoladi" | Texnik aktivda normallashtirilgan hostname (§2.4.7 qoidasi). CMDB ID ishlatilsa, `technical.hostname` albatta to'ldiriladi |
| Incidentdagi `affected_asset_uids` boshqa formatda yoki SOAR ichki ID si | Hodisa aktivga bog'lanmaydi | SOAR aktivining hostname'i, §2.4.7 qoidasi bo'yicha normallashtirilgan |
| MSSP bir nechta mijozni bitta snapshotda birlashtirgan | Ma'lumot rad etiladi | Har bir `org_id` uchun alohida so'rov |
| `asset_type` klassga mos emas (`hardware` + `responsible_person`) | `422` xatolik | Ilova E jadvalidan tekshirish |
| `personnel` aktivida `technical` obyekti | `422` xatolik — obyekt klassga mos emas | Faqat o'z klass obyekti |
| Texnik aktivda `technical` yoki `exposure` yo'q | `422` xatolik | `technical.exposure` majburiy |
| `personnel` da `name`, `email`, `login` | `422` — shaxsiy ma'lumot sxemada yo'q | Faqat `role_category` va `represents` |
| `site` da `address` yoki koordinata | `422` — maydon mavjud emas | `region_code` (ISO 3166-2:UZ) |
| `privileged_access: false` + `privileged_scope` | `422` — ziddiyatli holat | Yo `true` qilish, yo `privileged_scope` ni olib tashlash |
| `represents: "individual"` + `headcount` | `422` — bitta shaxsning soni bo'lmaydi | `represents: "group"` |
| `contains_pii: false` + `pii_volume_band: "under_1k"` | `422` — ziddiyat | `pii_volume_band: "none"` |
| `asset_type: "personal_data"` + `confidentiality_marks: ["KT"]` | `422` — tur va toifa mos emas | `PD` belgisini qo'shish |
| `confidentiality_marks: ["OD", "KO"]` | `422` — ochiq va konfidensial birga | Yo `["OD"]`, yo cheklangan kodlar |
| `as_protection_class` serverda | `422` — faqat avtomatlashtirilgan tizimlarda | `information_resource/information_system` aktiviga yozish |
| `country_code: "uz"` | `422` — kichik harf | `"UZ"` — ISO 3166-1 alpha-2, katta harf |
| `org_ref` ga jismoniy shaxs STIR i | Shaxsiy ma'lumot UzCORE ga tushadi | Faqat yuridik shaxs kodi |
| `retention_days` o'rniga `"5 yil"` | `422` — tur integer | `1825` |
| `personnel` da `asset_uid` = xodim ismi yoki login | Shaxsiy ma'lumot UzCORE ga tushadi | Anonim ID: `role-ciso`, `user-0417` |
| Aktivni ro'yxatdan chiqarib "o'chirdim" deb hisoblash | Aktiv bazada qoladi (upsert) | `lifecycle_status: "decommissioned"` yuborish |
| `known_cves` ga `cvss_score` yoki `kev_listed` yozilgan | `422` xatolik | Faqat `cve_id`, `status`, `detected_at` |
| `tlp` = `AMBER` | So'rov rad etiladi | Aktivlar uchun faqat `RED` |

---

# 5. Minimal majburiy to'plam

Agar tashkilotda to'liq sxemani amalga oshirish imkoni bo'lmasa, quyidagi qisqartirilgan to'plam **birinchi bosqichda** qabul qilinadi. Qolgani keyin qo'shiladi va bu modelni buzmaydi.

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

> ## Uchta maydon hech qachon tushirib qoldirilmaydi
>
> | Maydon | Nima beradi |
> |---|---|
> | `technical.affected_asset_uids` | Hodisalarni real aktivlarga bog'laydi (aktivlar ma'lum bo'lganda) |
> | `technical.indicators[].value` | Tashkilotlararo kampaniyani aniqlaydi |
> | `assets[].technical.known_cves` | Milliy CVE erta ogohlantirishini ishga tushiradi |
>
> 

---

# 6. Validatsiya cheklisti

Integratsiyani ishga tushirishdan oldin quyidagilarni tekshiring:

**Umumiy**
- [ ] `GET /connector/me` muvaffaqiyatli javob qaytardi
- [ ] `key` kodda emas, muhit o'zgaruvchisi yoki secret manager'da
- [ ] Tana bir marta serializatsiya qilinadi: hash'lanadigan va yuboriladigan baytlar aynan bir xil
- [ ] Barcha vaqtlar UTC da, incident/asset uchun `Z` bilan ISO 8601, alert ichida epoch **ms**
- [ ] Konvertdagi `org_id` — ma'lumot **egasi** bo'lgan tashkilot (yuboruvchi emas)
- [ ] Bitta so'rovda bitta `org_id` — MSSP mijozlari aralashtirilmagan
- [ ] Tanada `sender_id` yo'q — yuboruvchi `x-org-id` header'i orqali aniqlanadi
- [ ] Xom log, parol, buyruq qatori, xodim ismi yo'q
- [ ] `422` javobidagi `errors` massivi loglanadi va o'qiladi

**Incident**
- [ ] `report_id` §1.5 formulasi bo'yicha hisoblangan (tasodifiy emas)
- [ ] `source_case_id` to'ldirilgan va hodisa hayoti davomida o'zgarmaydi
- [ ] Bir hodisa = bir `report_id`, yangilanishlarda ham
- [ ] `related_report_ids` faqat boshqa hodisalarga havola qiladi (o'z `report_id` sini o'z ichiga olmaydi)
- [ ] `tlp` har bir hodisa elementida bor (konvertda emas)
- [ ] `status_id` manba tizimdan Ilova B.5 bo'yicha mapping qilingan, faqat `1`–`5` oralig'ida
- [ ] `status_id` = `5` bo'lganda `closed_at` to'ldirilgan
- [ ] `event_type` tanlangan `event_category` ga mos (Ilova A)
- [ ] `detected_at` ≤ `opened_at` ≤ `updated_at`
- [ ] `affected_asset_uids` aktivlar ma'lum bo'lsa to'ldirilgan, SOAR ichki ID si emas — §2.4.7 bo'yicha normallashtirilgan hostname; aks holda `[]`
- [ ] `indicators[].value` refang qilingan, kichik harfda, RFC 1918 filtrlangan
- [ ] `actions_taken` va `closing_note` da xost nomi / IP / login yo'q
- [ ] `activity` — to'liq tarix, faqat yangi yozuvlar emas
- [ ] `activity` da izoh matni yo'q, faqat `time` va `type`
- [ ] `status_changed` yozuvlarida `to_status_id` to'ldirilgan

**Alert**
- [ ] So'rov tanasi — konvert obyekti, `alerts[]` massivi uning ichida
- [ ] `org_id` va `collected_at` konvertda, alert elementlari ichida emas
- [ ] `class_uid`=2004, `category_uid`=2, `activity_id`=1, `type_uid`=200401
- [ ] `metadata.version` = `"1.9.0"`
- [ ] `severity_id` faqat `{0,1,2,3,4,5,99}` dan
- [ ] `finding_info.title` — qoida nomi, hodisa matni emas
- [ ] `device.hostname` normallashtirilgan va `asset_uid` ga teng
- [ ] `device.mac` kichik harfda (`00:1a:2b:3c:4d:5e`)

**Asset**
- [ ] `tlp` = `"RED"`
- [ ] `asset_uid` barqaror va snapshotlar orasida o'zgarmaydi
- [ ] `asset_type` tanlangan `asset_class` ga mos (Ilova E)
- [ ] Har bir aktivda faqat o'z klassiga mos obyekt; texnik klasslarda `technical.exposure` bor
- [ ] Registr obyektlarida faqat §4.4.6 dagi maydonlar; bog'liq maydonlar bir-biriga zid emas (`privileged_access`/`privileged_scope`, `represents`/`headcount`, `contains_pii`/`pii_volume_band`, `confidentiality_marks`/`asset_type`, `PD`/`contains_pii`)
- [ ] `site` da aniq manzil yo'q — faqat `region_code`; `organization.org_ref` faqat yuridik shaxs STIR i
- [ ] `personnel` aktivlarida `asset_uid` anonim — ism, login, email yo'q
- [ ] `technical.os.type_id`: Linux = **200**, Windows = **100** (Ilova B.4)
- [ ] `technical.mac_addresses[]` kichik harfda — alert `device.mac` bilan bir xil formatda
- [ ] `technical.known_cves[].cve_id` katta harfda, `CVE-YYYY-NNNN+` formatida; CVSS/KEV yuborilmagan
- [ ] O'chirilgan aktivlar `lifecycle_status: "decommissioned"` bilan yuborilgan

**Bog'lanish testi (eng muhimi)**
- [ ] Bitta test aktivi tanlandi
- [ ] Uning `asset_uid` i asset snapshotda bor
- [ ] Xuddi shu qiymat incident `affected_asset_uids` da bor
- [ ] Xuddi shu qiymat alert `device.hostname` da bor
- [ ] Uchalasi **belgima-belgi** bir xil

---

# Ilova A — ENISA RSIT hodisa klassifikatsiyasi (to'liq katalog)

`classification.event_category` va `classification.event_type` faqat quyidagi jadvaldan olinadi. **`event_type` tanlangan kategoriyaga tegishli bo'lishi shart** — boshqa kategoriyaning turi qabul qilinmaydi.

Uchinchi ustunda ENISA ning rasmiy yozilishi ko'rsatilgan (chiziqcha bilan). UzCORE pastki chiziq (`_`) shaklini qabul qiladi va ichkarida ENISA shakliga o'giradi — bu boshqa milliy CSIRT lar bilan almashinuvni ta'minlaydi.

### 1. `abusive_content` — suiiste'mol kontent

| `event_type` | ENISA yozilishi | Ta'rif |
|---|---|---|
| `spam` | `spam` | So'ralmagan ommaviy xabarlar |
| `harmful_speech` | `harmful-speech` | Kamsitish, tahdid, tuhmat |
| `violence` | `violence` | Zo'ravonlik, bolalarga nisbatan noqonuniy kontent |

### 2. `malicious_code` — zararli dastur

| `event_type` | ENISA yozilishi | Ta'rif |
|---|---|---|
| `infected_system` | `infected-system` | Zararlangan tizim. **Ransomware ham shu yerga kiradi.** |
| `c2_server` | `c2-server` | Boshqaruv (C&C) serveri |
| `malware_distribution` | `malware-distribution` | Zararli dastur tarqatuvchi resurs |
| `malware_configuration` | `malware-configuration` | Zararli dastur konfiguratsiyasi |

### 3. `information_gathering` — ma'lumot to'plash

| `event_type` | ENISA yozilishi | Ta'rif |
|---|---|---|
| `scanner` | `scanner` | Port/zaiflik skanerlash |
| `sniffing` | `sniffing` | Tarmoq trafigini tinglash |
| `social_engineering` | `social-engineering` | Ijtimoiy muhandislik (phishing dan tashqari) |

### 4. `intrusion_attempts` — kirish urinishlari

| `event_type` | ENISA yozilishi | Ta'rif |
|---|---|---|
| `exploit` | `exploit` | Ma'lum zaiflikni ekspluatatsiya qilishga urinish |
| `brute_force` | `brute-force` | Kirish ma'lumotlarini saralash |
| `ids_alert` | `ids-alert` | Yangi/noma'lum hujum imzosi |

### 5. `intrusions` — muvaffaqiyatli kirish

| `event_type` | ENISA yozilishi | Ta'rif |
|---|---|---|
| `privileged_account_compromise` | `privileged-account-compromise` | Imtiyozli hisob buzildi |
| `unprivileged_account_compromise` | `unprivileged-account-compromise` | Oddiy hisob buzildi |
| `application_compromise` | `application-compromise` | Ilova buzildi |
| `system_compromise` | `system-compromise` | Tizim to'liq buzildi |
| `burglary` | `burglary` | Fizik kirish |

### 6. `availability` — mavjudlik

| `event_type` | ENISA yozilishi | Ta'rif |
|---|---|---|
| `dos` | `dos` | Xizmatdan voz kechtirish |
| `ddos` | `ddos` | Taqsimlangan DoS |
| `misconfiguration` | `misconfiguration` | Noto'g'ri sozlash natijasidagi uzilish |
| `sabotage` | `sabotage` | Ataylab zarar yetkazish |
| `outage` | `outage` | Hujum bilan bog'liq bo'lmagan uzilish |

### 7. `information_content_security` — ma'lumot xavfsizligi

| `event_type` | ENISA yozilishi | Ta'rif |
|---|---|---|
| `unauthorised_information_access` | `unauthorised-information-access` | Ruxsatsiz kirish |
| `unauthorised_information_modification` | `unauthorised-information-modification` | Ruxsatsiz o'zgartirish |
| `data_leak` | `data-leak` | Maxfiy ma'lumot chiqib ketishi |
| `data_loss` | `data-loss` | Ma'lumot yo'qolishi |

### 8. `fraud` — firibgarlik

| `event_type` | ENISA yozilishi | Ta'rif |
|---|---|---|
| `unauthorised_use_of_resources` | `unauthorized-use-of-resources` | Resurslardan ruxsatsiz foydalanish (masalan kripto-mayning) |
| `copyright` | `copyright` | Mualliflik huquqi buzilishi |
| `masquerade` | `masquerade` | Boshqa shaxs nomidan ish yuritish |
| `phishing` | `phishing` | Fishing |

### 9. `vulnerable` — zaiflik (hodisa emas, holat)

| `event_type` | ENISA yozilishi | Ta'rif |
|---|---|---|
| `weak_crypto` | `weak-crypto` | Zaif kriptografiya |
| `ddos_amplifier` | `ddos-amplifier` | DDoS kuchaytirgichi bo'la oladigan xizmat |
| `potentially_unwanted_accessible` | `potentially-unwanted-accessible` | Ochiq qolgan keraksiz xizmat |
| `information_disclosure` | `information-disclosure` | Ma'lumot oshkor bo'lishi |
| `vulnerable_system` | `vulnerable-system` | Zaiflikka ega tizim |

### 10. `other` — boshqa

| `event_type` | ENISA yozilishi | Ta'rif |
|---|---|---|
| `other` | `other` | Yuqoridagilarga to'g'ri kelmaydi |
| `undetermined` | `undetermined` | Tur hali aniqlanmagan |

### A.1 Amaliy misollar — qanday klassifikatsiya qilinadi

| Vaziyat | `event_category` | `event_type` | Qo'shimcha |
|---|---|---|---|
| LockBit ransomware serverni shifrladi | `malicious_code` | `infected_system` | `mitre_attacks`: TA0040 → T1486 |
| SSH parolini saralash urinishlari | `intrusion_attempts` | `brute_force` | `mitre_attacks`: TA0006 → T1110 → T1110.001 |
| SSH saralash **muvaffaqiyatli** bo'ldi | `intrusions` | `unprivileged_account_compromise` | Urinish emas, kirish |
| Xodimga fishing xat keldi, bosmadi | `fraud` | `phishing` | — |
| Fishing orqali kredensial o'g'irlandi | `intrusions` | `unprivileged_account_compromise` | `mitre_attacks`: TA0001 → T1566 |
| Sayt DDoS ostida | `availability` | `ddos` | — |
| Mijozlar bazasi internetga chiqib qoldi | `information_content_security` | `data_leak` | `severity_id: 5` |
| Web-server CVE orqali buzildi | `intrusions` | `application_compromise` | `mitre_attacks`: TA0001 → T1190; CVE `alerts[]` orqali bog'lanadi |
| Serverda kripto-mayner topildi | `fraud` | `unauthorised_use_of_resources` | — |
| Domen kontrolleri to'liq egallandi | `intrusions` | `privileged_account_compromise` | `criticality: crown_jewel` |
| Tashqi manzil portlarni skanerlamoqda | `information_gathering` | `scanner` | — |
| Firewall qoidasi noto'g'ri, xizmat uzildi | `availability` | `misconfiguration` | — |

# Ilova B — OCSF 1.9.0 enum katalogi

Bu ro'yxatlar `https://schema.ocsf.io/1.9.0/` dan olingan. Rasmiy manba har doim ustun turadi — shubha bo'lsa shu saytni tekshiring.

**Umumiy qoida:** `0` = Unknown (noma'lum), `99` = Other (kataloqqa tushmaydi). Oraliq raqamlar o'ylab topilmaydi.

### B.1 `severity_id` (alert va incident uchun bir xil)

| ID | Nomi |
|---|---|
| `0` | Unknown — manba xavflilik darajasi bermagan |
| `1` | Informational |
| `2` | Low |
| `3` | Medium |
| `4` | High |
| `5` | Critical |
| `99` | Other |

### B.2 Alert: `status_id`

| ID | Nomi |
|---|---|
| `0` | Unknown |
| `1` | New |
| `2` | In Progress |
| `3` | Suppressed — ko'rib chiqilgan, false positive deb topilgan |
| `4` | Resolved |
| `5` | Archived |
| `99` | Other |

**Manba tizimlardan mapping:**

| Manba qiymati | `status_id` |
|---|---|
| Sentinel `New` · Defender `new` · Elastic `open` · Splunk `new` · QRadar `OPEN` | `1` New |
| Sentinel `Active` · Defender `inProgress` · Elastic `acknowledged` · Splunk `in progress` | `2` In Progress |
| QRadar `HIDDEN` · false positive deb yopilgan alertlar | `3` Suppressed |
| Defender `resolved` · Splunk `resolved` | `4` Resolved |
| Sentinel `Closed` · Elastic `closed` · Splunk `closed` · QRadar `CLOSED` | `5` Archived |
| Wazuh — holat tushunchasi yo'q | maydon yuborilmaydi |

> **DIQQAT:** alert va incident `status_id` enumlari **bir xil emas**. `3` alertda **Suppressed**, incidentda **On Hold**; `5` alertda **Archived**, incidentda **Closed**. Bu OCSF ning o'zida shunday — Detection Finding va Incident Finding alohida klasslar. Incident uchun **Ilova B.5** jadvalidan foydalaning.

### B.3 `observables[].type_id`

| ID | Nomi |
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

### B.4 `os.type_id` — eng ko'p xato qilinadigan enum

| ID | Nomi | Nima kiradi |
|---|---|---|
| `0` | Unknown | — |
| `100` | Windows | Windows 10/11, Windows Server 2016/2019/2022 |
| `101` | Windows Mobile | — |
| `200` | Linux | Ubuntu, RHEL, CentOS, Debian, SUSE, Alpine, Rocky, Alma |
| `201` | Android | Faqat Android. Linux emas! |
| `300` | macOS | — |
| `301` | iOS | — |
| `302` | iPadOS | — |
| `400` | Solaris | — |
| `401` | AIX | — |
| `402` | HP-UX | — |
| `99` | Other | FreeBSD, Cisco IOS, mualliflik OT lari |

> **Faqat shu qiymatlar mavjud.** `1`, `102`, `202`, `203`, `403` — OCSF da yo'q, rad etiladi.

### B.5 Incident: `status_id` — manba tizimlardan mapping

Har bir tashkilotning SOAR/SIEM tizimi o'z holat nomlarini ishlatadi. UzCORE ga yuborishdan oldin ular **majburiy ravishda** `status_id` raqamiga o'giriladi — manba matni to'g'ridan-to'g'ri yuborilmaydi.

**Ruxsat etilgan qiymatlar — faqat beshta:**

| ID | Nomi | Ma'nosi |
|---|---|---|
| `1` | New | Case ochilgan, hali hech kim ishlamagan |
| `2` | In Progress | Analitik ish olib bormoqda |
| `3` | On Hold | Ish vaqtincha to'xtatilgan — tashqi tomon javobi kutilmoqda |
| `4` | Resolved | Texnik ish tugagan, case rasman yopilmagan |
| `5` | Closed | Case yopilgan, `closed_at` to'ldirilgan |

`0` (Unknown) va `99` (Other) **ataylab yo'q**: case har doim shu beshta holatdan birida bo'ladi.

**Kengaytirilgan mapping — mumkin bo'lgan yozilishlar:**

| Manba holati (turli yozilishlar) | `status_id` |
|---|---|
| New · Draft · Open · Opened · Created · Pending · To Do · Unassigned · Yangi | `1` |
| In Progress · In Process · InProgress · In-Progress · Active · Investigating · Analysis · Triage · Assigned · Working · Contain · Eradicate · Recover · Jarayonda | `2` |
| On Hold · OnHold · On-Hold · Hold · Awaiting · Awaiting Caller · Awaiting Vendor · Awaiting Info · Waiting · Suspended · Paused · Deferred · Kutilmoqda | `3` |
| Resolved · Done · Remediated · Mitigated · Review · Pending Closure · Hal qilindi | `4` |
| Closed · Completed · Archive · Archived · Cancelled · Canceled · Duplicated · Rejected · Yopildi | `5` |

**Keng tarqalgan tizimlar bo'yicha:**

| Manba tizim | Manba holati | `status_id` |
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

**Mapping qoidalari:**

- **NIST bosqichlari `status_id` ga tushmaydi.** ServiceNow SecOps dagi Contain / Eradicate / Recover holatlari — hammasi `status_id: 2` (In Progress). Texnik bosqich `response.containment_status` da ifodalanadi.
- **`4` Resolved va `5` Closed farqi:** Resolved — texnik ish tugadi, lekin case rasman yopilmagan (odatda tasdiqlash kutilmoqda). Closed — case yopilgan va `closed_at` to'ldirilgan.
- **Mos qiymat topilmasa**, jadvaldan **eng yaqin** mosini tanlang. `0` yoki `99` yuborish imkoni yo'q — ular sxemada rad etiladi.
- Ro'yxatda yo'q tizim uchun mapping jadvalini o'zingiz tuzing va uni UzCORE ga onboarding paytida taqdim eting.

### B.6 Incident: `verdict_id` — tergov xulosasi

`verdict_id` — hodisa **tergov qilingandan keyin** analitik chiqargan xulosa. `status_id` dan farqi: `status_id` ish **qayerda** ekanini, `verdict_id` esa natija **qanday** ekanini bildiradi.

**UzCORE uchun nima beradi:** false-positive nisbati sektor bo'yicha (agar hodisalarning katta qismi `1` bo'lsa, o'sha sektorning aniqlash qoidalari sozlanmagan); milliy statistikadan xato signallarni chiqarib tashlash; dublikatlarni ikki marta sanamaslik.

| ID | Nomi | Qachon ishlatiladi |
|---|---|---|
| `0` | Unknown | Tergov davom etmoqda, hukm hali chiqarilmagan. Ochiq hodisalarda odatdagi qiymat. |
| `1` | False Positive | Hodisa bo'lmagan — vosita xato signal bergan. Qoidani sozlash kerakligini bildiradi. |
| `2` | True Positive | Haqiqiy xavfsizlik hodisasi tasdiqlangan. |
| `3` | Disregard | Haqiqiy, lekin e'tiborga olinmaydi — ahamiyatsiz, xato yoki tasodif. |
| `4` | Suspicious | Shubhali faoliyat, lekin zararli ekani tasdiqlanmagan. |
| `5` | Benign | Haqiqiy faoliyat, lekin zararsiz — masalan administrator o'zi bajargan ish, rejalashtirilgan test. |
| `6` | Test | Mashq, sinov yoki pentest hodisasi. Milliy statistikadan chiqariladi. |
| `7` | Insufficient Data | Xulosa chiqarish uchun ma'lumot yetarli emas — loglar o'chib ketgan, aktivga kirish yo'q. |
| `8` | Security Risk | Hujum emas, lekin xavfsizlik muammosi aniqlangan — noto'g'ri sozlash, zaiflik. |
| `9` | Managed Externally | Hodisani boshqa tomon hal qilgan — provayder, vendor, boshqa SOC. |
| `10` | Duplicate | Boshqa hodisaning takrori. `related_report_ids` bilan birga ishlatiladi — u qaysi hodisaga dublikat ekanini ko'rsatadi. |

`99` (Other) **ataylab yo'q**: yuqoridagi o'n bitta qiymat barcha amaliy holatlarni qoplaydi.

**Manba tizimlardan mapping:**

| Manba qiymati | `verdict_id` |
|---|---|
| TheHive `TruePositive` · XSOAR `Resolved - True Positive` · Sentinel `TruePositive` | `2` |
| TheHive `FalsePositive` · Sentinel `FalsePositive` · XSOAR `False Positive` | `1` |
| TheHive `Duplicated` · XSOAR `Duplicate` | `10` |
| Sentinel `BenignPositive` · Kaspersky `Low priority` | `5` |
| TheHive `Indeterminate` · Sentinel `Undetermined` | `0` yoki `7` (ma'lumot yetishmasa `7`) |
| Test yoki mashq hodisasi · XSOAR `Test` | `6` |
| Boshqa tomon hal qilgan | `9` |

**Qachon to'ldiriladi:** hodisa ochiq bo'lganda `0` (yoki maydon umuman yozilmaydi), yopilganda esa haqiqiy xulosa. `status_id: 5` bilan `verdict_id: 0` juftligi — tugallanmagan ish belgisi.

### B.7 Incident: `containment_status` — javob bosqichi

NIST SP 800-61 javob siklining qaysi bosqichida ekanini bildiradi. `status_id` (ish jarayoni) bilan **takrorlanmaydi**.

| Qiymat | Ma'nosi |
|---|---|
| `not_contained` | Lokalizatsiya qilinmagan, hujum davom etmoqda |
| `partially_contained` | Qisman lokalizatsiya qilingan |
| `contained` | Lokalizatsiya qilingan, tarqalish to'xtatilgan |
| `eradicated` | Zararli komponent tizimdan olib tashlangan |
| `recovered` | Tizim normal ishga qaytgan |

### B.8 Incident: `activity[].type` — xronologiya voqealari

| Qiymat | Qachon yoziladi | Qo'shimcha maydon |
|---|---|---|
| `case_opened` | Case ochildi | — |
| `case_closed` | Case yopildi | — |
| `case_reopened` | Yopilgan case qayta ochildi | — |
| `status_changed` | Holat o'zgardi | `to_status_id` (majburiy) |
| `comment_added` | Izoh yozildi (**matn yuborilmaydi**) | — |
| `task_created` | Vazifa qo'yildi | — |
| `task_completed` | Vazifa bajarildi | — |
| `severity_changed` | Xavflilik qayta baholandi | `to_severity_id` (majburiy) |
| `artifact_added` | Yangi IOC yoki dalil qo'shildi | — |
| `other` | Yuqoridagilarga to'g'ri kelmaydi | — |

### B.9 ATT&CK taktikalari katalogi

Hujum bosqichi incidentda `technical.mitre_attacks[].tactic`, alertda `finding_info.attacks[].tactic.uid` orqali ifodalanadi. Manba tizim faqat taktika nomini bersa, ID ni shu jadvaldan toping.

| `tactic.uid` | Nomi |
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

# Ilova C — Manba tizimlardan maydonlarni olish

Amaliy yordam: keng tarqalgan vositalarda kerakli ma'lumot qayerda turadi.

### C.1 IOC (`indicators[]`) qayerdan olinadi

| Tizim | Manba | Filtr |
|---|---|---|
| **TheHive** | Case **observables** (`dataType`, `data`, `tlp`) | Faqat `ioc: true` bo'lganlari |
| **Cortex XSOAR** | Incident **indicators** (extraction rules natijasi) | Reputation/verdict bo'yicha |
| **Microsoft Sentinel** | Incident **entities** | Entity ≠ IOC. Jabrlanuvchi xost va foydalanuvchini chiqarib tashlash |
| **Splunk SOAR** | Container **artifacts**, CEF maydonlari (`sourceAddress`, `fileHash`, `requestURL`) | CEF kaliti → `type` mapping jadvali kerak |
| **IBM QRadar SOAR** | **Artifacts** (IP Address, DNS Name, SHA-256, URL) | Turlangan, to'g'ridan-to'g'ri mos keladi |
| **Wazuh** | **Case obyekti yo'q.** Alert maydonlaridan olinadi: `data.srcip`, `data.dstip`, `data.url`, `syscheck.sha256_after` | Har bir dekoder uchun alohida mapping |

### C.2 Wazuh dan OCSF ga asosiy mapping

| Wazuh maydoni | OCSF maydoni | Izoh |
|---|---|---|
| `id` | `finding_info.uid` | Idempotentlik kaliti |
| `rule.id` | `metadata.event_code` | — |
| `rule.description` | `finding_info.title`, `metadata.event_name` | — |
| `rule.level` (0–15) | `severity_id` | Quyidagi mapping jadvali bo'yicha (§3.4.3) |
| `rule.mitre.id` | `finding_info.attacks[].technique.uid` | Incidentda `technical.mitre_attacks[].techniques[].uid` |
| `rule.mitre.tactic` (nom) | `finding_info.attacks[].tactic.uid` | Nomdan ID ga o'girish kerak — Ilova B.9 |
| `rule.firedtimes` | `count` | — |
| `timestamp` | `time` (epoch ms) | ISO 8601 dan epoch ms ga o'girish majburiy |
| `agent.name` | `device.hostname` | **Normallashtirilgan holda** — `assets[].asset_uid` ga teng |
| `agent.ip` | `device.ip` | — |
| `data.srcip` | `observables[]` `type_id: 2` | RFC 1918 filtrlanadi |
| `syscheck.sha256_after` | `observables[]` `type_id: 8` | — |
| `data.vulnerability.cve` | `vulnerabilities[].cve.uid` | — |
| `full_log` | — | **Yuborilmaydi** — maxfiylik sabab |

**Wazuh `rule.level` → `severity_id` tavsiya etilgan mapping:**

| `rule.level` | `severity_id` | Nomi |
|---|---|---|
| 0–3 | `1` | Informational |
| 4–6 | `2` | Low |
| 7–9 | `3` | Medium |
| 10–12 | `4` | High |
| 13–15 | `5` | Critical |

---

# Ilova D — Rasmiy JSON Schema fayllari

Hujjat bilan birga uchta JSON Schema fayli beriladi. Ular **JSON Schema draft 2020-12** standartida yozilgan va hujjatdagi barcha qoidalarni mashina o'qiy oladigan shaklda ifodalaydi.

| Fayl | Nima uchun |
|---|---|
| `incident-report.schema.json` | Incident to'plami (konvert + `incidents[]`) |
| `alert.schema.json` | Alert to'plami (konvert + `alerts[]`) |
| `asset-inventory.schema.json` | Asset to'plami (konvert + `assets[]`): umumiy yadro + klassga mos obyekt |

**Ular nimani ushlaydi:**
- RSIT `event_category` ↔ `event_type` mosligi (`if`/`then` orqali, har bir kategoriya uchun alohida)
- Shartli majburiylik: `closed_at` (`status_id` 5 da); alertda `end_time` bo'lsa `start_time`; asset uchun `asset_type` ↔ `asset_class` mosligi va har bir klassda faqat o'z obyekti (`technical` yoki registr obyekti)
- `additionalProperties: false` — sxemada yo'q maydonlar rad etiladi
- Format qoidalari: UUID, ISO 8601 `Z` bilan, `CVE-YYYY-NNNN+`, CPE 2.3, MITRE `T####[.###]`
- OCSF enumlari: `severity_id`, `status_id`, `os.type_id`, `observables[].type_id` va boshqalar

**Sxema ushlay olmaydigan, server tekshiradigan qoidalar:** `start_time ≤ end_time`, `detected_at ≤ opened_at ≤ updated_at`, `summary` qiymatlarining `assets[]` bilan mosligi.

**Ishlatish — Python:**

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

# Ilova E — Aktiv taksonomiyasi (klass va turlar)

Taksonomiya **O'zMSt 816:2025** §7.9.2 (himoya obyektlari) asosida tuzilgan va **O'zMSt ISO/IEC 27005:2024**, **ISO/IEC 27001:2022 Annex A** hamda O'zbekiston Prezidentining **ПҚ-167** qarori ([lex.uz/docs/6479190](https://lex.uz/docs/6479190)) bilan kengaytirilgan. `asset_class` va `asset_type` qiymatlari aynan quyidagicha yoziladi.

**Qanday tanlanadi:** avval aktivning klassini aniqlang, so'ng shu klass ichidan eng mos turni tanlang. Bitta aktiv faqat bitta klassga tegishli. Aktivlar orasidagi bog'liqlik `related_asset_uids` orqali ko'rsatiladi (O'zMSt ISO/IEC 27005:2024 A.2.2 — aktivlar bog'liqligi grafigi).

`iso27005_category` ustuni aktivning turini bildiradi: **primary** — asosiy (ma'lumot va jarayonlar), **supporting** — yordamchi (ularni tashuvchi resurslar).

**816 dan ikki ongli chetlanish:** `source_code` — 816 da dasturiy ta'minot tarkibida (§7.9.2 c)3)), bu yerda `information` klassida, chunki manba kodi ma'lumot sifatida himoyalanadi va unda tarmoq xususiyatlari bo'lmaydi. `passive_network_equipment` — 816 da tarmoq tarkibida (§7.9.2 c)4)), bu yerda `site` klassida, chunki shkaf va kabel kanallari jismoniy infratuzilma.

| Klass | Turlar soni | Obyekt |
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

Jami: **12 klass, 70 tur.**

### E.1 `information`

| `asset_type` | ISO 27005 | Tavsif | Asos |
|---|---|---|---|
| `processed_data` | primary | Raqamli, moddiy yoki nomoddiy shakldagi ma'lumotlar | 816: §7.9.2 a); 27005: A.2.2; 27001: A.5.9; ПҚ-167: §11, §13 |
| `state_secret` | primary | Davlat sirlari (SS – sir tutilgan; S – maxfiy) | 816: §7.9.2 a); L ilova; 27005: A.2.2; 27001: A.5.12 |
| `confidential_data` | primary | Konfidensial ma'lumotlar (DSP – xizmatda foydalanish uchun; KT – tijorat siri; BT – bank siri; KO – tashkilot konfidensial ma'lumotlari) | 816: §7.9.2 a); L ilova; 27005: A.2.2; 27001: A.5.12 |
| `personal_data` | primary | Shaxsga doir ma'lumotlar (PD) | 816: §7.9.2 a); L ilova; 27005: A.2.2; 27001: A.5.34 |
| `public_data` | primary | Ochiq ma'lumotlar (OD) | 816: L ilova; 27005: A.2.2; 27001: A.5.12 |
| `transmitted_data` | primary | Aloqa kanallari orqali uzatiladigan ma'lumotlar | 816: §7.9.2 c)4); 27005: A.2.2; 27001: A.8.20; ПҚ-167: §12 |
| `source_code` | supporting | Manba kodlari | 816: §7.9.2 c)3); 27005: A.2.2; 27001: A.8.4 |
| `configuration` | supporting | Tizim va qurilmalarning konfiguratsiya fayllari, arxitektura | 816: L.1-jadval (9); 27005: A.2.2; 27001: A.8.9; ПҚ-167: §11–§13 |
| `backup` | supporting | Zaxira nusxalari | 816: L.1-jadval (1); 27005: A.2.2; 27001: A.8.13 |
| `credential` | supporting | Autentifikatsiya ma'lumotlari | 27005: A.2.2; 27001: A.5.17 |
| `cryptographic_key` | supporting | Kriptografik kalitlar | 27005: A.2.2; 27001: A.8.24 |
| `log_data` | supporting | Audit va hodisalar jurnallari | 27005: A.2.2; 27001: A.8.15 |

### E.2 `process`

| `asset_type` | ISO 27005 | Tavsif | Asos |
|---|---|---|---|
| `business_process` | primary | Tashkilotning biznes-jarayonlari | 816: §7.9.5 c); 27005: A.2.2; 27001: A.5.30 |

### E.3 `hardware`

| `asset_type` | ISO 27005 | Tavsif | Asos |
|---|---|---|---|
| `endpoint` | supporting | Foydalanuvchilarning oxirgi qurilmalari | 816: §7.9.2 c)1); 27005: A.2.2 (apparat); 27001: A.8.1; ПҚ-167: §11 |
| `server` | supporting | Serverlar | 816: §7.9.2 c)1); 27005: A.2.2 (apparat); 27001: A.8.1; ПҚ-167: §11 |
| `industrial_server` | supporting | Sanoat serverlari (ABT) | 27005: A.2.2 (apparat); ПҚ-167: §13 |
| `storage_system` | supporting | Ma'lumotlarni saqlash tizimlari | 816: §7.9.2 c)1); 27005: A.2.2 (apparat); 27001: A.7.10; ПҚ-167: §11 |
| `removable_media` | supporting | Olinadigan axborot tashuvchilar | 816: §7.9.2 c)1); 27005: A.2.2 (apparat); 27001: A.7.10; ПҚ-167: §6 |
| `mobile` | supporting | Mobil qurilmalar | 816: §7.9.2 c)2); 27005: A.2.2 (apparat); 27001: A.8.1; ПҚ-167: §11 |
| `atm` | supporting | Bankomatlar | 816: §7.9.2 c)2); 27005: A.2.2 (apparat) |
| `infokiosk` | supporting | Infokiosklar | 816: §7.9.2 c)2); 27005: A.2.2 (apparat) |
| `payment_terminal` | supporting | To'lov terminallari | 816: §7.9.2 c)2); 27005: A.2.2 (apparat) |
| `plc` | supporting | Dasturlanadigan mantiqiy tekshirgichlar | 27005: A.2.2 (apparat); ПҚ-167: §13 |
| `technological_equipment` | supporting | Ishlab chiqarish va texnologik uskunalar | 27005: A.2.2 (apparat); ПҚ-167: §13 |
| `iot_device` | supporting | Boshqa alohida qurilmalar (IoT) | 816: §7.9.2 c)2); 27005: A.2.2 (apparat); 27001: A.8.1 |
| `virtual_machine` | supporting | Virtual mashinalar | 27005: A.2.2 (apparat); 27001: A.8.9; ПҚ-167: §14 |
| `container` | supporting | Konteynerlar | 27005: A.2.2 (apparat); 27001: A.8.9; ПҚ-167: §14 |
| `media_processing_device` | supporting | Grafik, video va nutq ma'lumotlarini qayta ishlash vositalari | 27005: A.2.2 (apparat); ПҚ-167: §11 |

### E.4 `software`

| `asset_type` | ISO 27005 | Tavsif | Asos |
|---|---|---|---|
| `operating_system` | supporting | Operatsion tizimlar | 816: §7.9.2 c)3); 27005: A.2.2 (ilova); 27001: A.8.19; ПҚ-167: §11–§13 |
| `application` | supporting | Amaliy dasturiy ta'minot va ilovalar | 816: §7.9.2 c)3); 27005: A.2.2 (ilova); 27001: A.8.26; ПҚ-167: §11–§13 |
| `dbms` | supporting | Ma'lumotlar bazasini boshqarish tizimlari | 816: §7.9.2 c)3); 27005: A.2.2 (ilova); 27001: A.8.26; ПҚ-167: §11 |
| `diagnostic_tool` | supporting | Diagnostika dasturlari | 816: §7.9.2 c)3); 27005: A.2.2 (ilova); 27001: A.8.18 |
| `dev_tool` | supporting | Asbobli ishlab chiqish vositalari | 816: §7.9.2 c)3); 27005: A.2.2 (ilova); 27001: A.8.4 |
| `utility` | supporting | Yordamchi dasturlar | 816: §7.9.2 c)3); 27005: A.2.2 (ilova); 27001: A.8.18 |
| `firmware` | supporting | Apparat-dasturiy vositalarning dasturiy ta'minoti | 27005: A.2.2 (ilova); 27001: A.8.9; ПҚ-167: §11, §13 |

### E.5 `network`

| `asset_type` | ISO 27005 | Tavsif | Asos |
|---|---|---|---|
| `corporate_network` | supporting | Korporativ va/yoki lokal tarmoqlar | 816: §7.9.2 c)4); 27005: A.2.2 (tarmoq); 27001: A.8.20; ПҚ-167: §12 |
| `comm_channel` | supporting | Aloqa kanallari (korporativ, masofaviy ulanish, tashqi tarmoqlarga ulanish) | 816: §7.9.2 c)4); 27005: A.2.2 (tarmoq); 27001: A.8.20; ПҚ-167: §11–§13 |
| `active_network_device` | supporting | Faol tarmoq uskunalari – kalitlar, marshrutizatorlar, modemlar | 816: §7.9.2 c)4); 27005: A.2.2 (tarmoq); 27001: A.8.20; ПҚ-167: §12 |
| `network_segment` | supporting | Tarmoq segmenti – VLAN, DMZ | 816: §7.17 (VLAN); 27005: A.2.2 (tarmoq); 27001: A.8.22; ПҚ-167: §12 |
| `telecom_management_system` | supporting | Telekommunikatsiya tarmog'ining boshqaruv tizimi | 27005: A.2.2 (tarmoq); 27001: A.8.20; ПҚ-167: §12 |

### E.6 `service`

| `asset_type` | ISO 27005 | Tavsif | Asos |
|---|---|---|---|
| `email_system` | supporting | Elektron pochta | 816: §7.9.2 c)5); §8.6.2; 27005: A.2.2 (xizmat); 27001: A.5.14; ПҚ-167: §11 |
| `video_conferencing` | supporting | Videokonferensaloqa | 816: §7.9.2 c)5); 27005: A.2.2 (xizmat); 27001: A.5.14 |
| `ip_telephony` | supporting | IP-telefoniya | 816: §7.9.2 c)5); 27005: A.2.2 (xizmat); 27001: A.5.14 |
| `messaging` | supporting | Tezkor xabar almashish tizimlari (messenjerlar) | 816: §7.9.2 c)5); 27005: A.2.2 (xizmat); 27001: A.5.14 |
| `edms` | supporting | Elektron hujjat aylanishi tizimi | 816: §7.9.2 c)5); §8.6.2; 27005: A.2.2 (xizmat); 27001: A.5.14 |
| `identity_service` | supporting | Identifikatsiya va autentifikatsiya xizmati (domen nazoratchisi, IdP) | 816: L.1-jadval (9); 27005: A.2.2 (xizmat); 27001: A.5.16; ПҚ-167: §11 |
| `dns_service` | supporting | DNS xizmati | 27005: A.2.2 (xizmat); 27001: A.8.21 |
| `cloud_service` | supporting | Bulut xizmatlari | 27005: A.2.2 (xizmat); 27001: A.5.23 |
| `managed_service` | supporting | Tashqi yetkazib beruvchi xizmati | 27005: A.2.2 (xizmat); 27001: A.5.19 |

### E.7 `information_resource`

| `asset_type` | ISO 27005 | Tavsif | Asos |
|---|---|---|---|
| `file_storage` | supporting | Fayllarni saqlash tizimlari (fayl-server) | 816: §7.9.2 c)6); §8.6.2; 27005: A.2.2; 27001: A.8.3; ПҚ-167: §11 |
| `web_resource` | supporting | Ichki yoki tashqi veb-resurslar | 816: §7.9.2 c)6); §8.6.2; 27005: A.2.2; 27001: A.8.26; ПҚ-167: §11 |
| `database` | supporting | Lokal yoki axborot tizimiga kiruvchi ma'lumotlar bazasi | 816: §7.9.2 c)6); §8.6.2; 27005: A.2.2; 27001: A.8.26; ПҚ-167: §11 |
| `information_system` | supporting | Axborot (avtomatlashtirilgan) tizim | 816: §7.9.2 c); §7.9.4; 27005: A.2.2; 27001: A.8.9; ПҚ-167: §11 |
| `industrial_control_system` | supporting | Avtomatlashtirilgan boshqaruv tizimi (ABT) | 816: §7.9.3; 27005: A.2.2; ПҚ-167: §13 |

### E.8 `security_tool`

| `asset_type` | ISO 27005 | Tavsif | Asos |
|---|---|---|---|
| `security_appliance` | supporting | Axborotni himoya qilish apparat vositalari: tarmoqlararo ekran (NGFW), IDS/IPS, VPN-shlyuz, WAF qurilmalari (sertifikatlangan) | 816: §7.9.2 e); 27005: A.2.2 (apparat); 27001: A.8.20; ПҚ-167: §7, §12, §13 |
| `security_software` | supporting | Axborotni himoya qilish dasturiy vositalari: EDR, antivirus, DLP, SIEM agentlari (sertifikatlangan) | 816: §7.9.2 e); 27005: A.2.2 (ilova); 27001: A.8.7; ПҚ-167: §7, §12, §13 |

### E.9 `personnel`

| `asset_type` | ISO 27005 | Tavsif | Asos |
|---|---|---|---|
| `employee` | supporting | Tashkilot xodimlari | 816: §7.9.2 b); 27005: A.2.2 (inson resursi); 27001: A.6.1; ПҚ-167: §4 |
| `customer` | supporting | Mijozlar | 816: §7.9.2 b); 27005: A.2.2 (inson resursi) |
| `user` | supporting | Foydalanuvchilar (ichki va tashqi – mijozlar, hamkorlar, Internet foydalanuvchilari) | 816: §7.9.2 b); L ilova; 27005: A.2.2 (inson resursi); 27001: A.5.18 |
| `developer` | supporting | Ishlab chiquvchilar | 816: §7.9.2 b); 27005: A.2.2 (inson resursi); 27001: A.8.25 |
| `administrator` | supporting | Ma'murlar (imtiyozli foydalanuvchilar) | 27005: A.2.2 (inson resursi – ma'mur); 27001: A.8.2 |
| `responsible_person` | supporting | Axborot xavfsizligi uchun mas'ul shaxs yoki bo'linma | 816: §7.15; 27005: A.2.2 (inson resursi); 27001: A.5.2; ПҚ-167: §4, §5 |

### E.10 `site`

| `asset_type` | ISO 27005 | Tavsif | Asos |
|---|---|---|---|
| `office_room` | supporting | Himoyalangan xizmat va yig'ilish xonalari | 816: §7.9.2 d); 27005: A.2.2; 27001: A.7.1 |
| `server_room` | supporting | Server xonalari, kommutatsiya xonalari | 816: §7.9.2 d); 27005: A.2.2; 27001: A.7.4 |
| `backup_storage_room` | supporting | Zaxira vositalari, nusxalar va arxiv saqlanadigan xonalar (omborlar, arxivlar) | 816: §7.9.2 d); 27005: A.2.2; 27001: A.7.10 |
| `datacenter` | supporting | Ma'lumotlar markazi | 816: §7.9.2 d); 27005: A.2.2; 27001: A.7.4 |
| `passive_network_equipment` | supporting | Passiv tarmoq uskunalari – o'rnatish shkaflari, kabel kanallari, kommutatsiya panellari | 816: §7.9.2 c)4); 27005: A.2.2 (tarmoq); 27001: A.7.12; ПҚ-167: §12 |

### E.11 `organization`

| `asset_type` | ISO 27005 | Tavsif | Asos |
|---|---|---|---|
| `supplier` | supporting | Tashqi operator yoki yetkazib beruvchi | 816: §8.6.13; 27005: A.2.2; 27001: A.5.19 |
| `org_unit` | supporting | Tashkilot tarkibiy bo'linmasi (aktiv egasi sifatida) | 816: §8.6.10; 27005: A.2.2; 27001: A.5.2 |

### E.12 `intangible`

| `asset_type` | ISO 27005 | Tavsif | Asos |
|---|---|---|---|
| `reputation` | primary | Tashkilotning obro'si va imidji | 816: §7.9.2 f); 27005: A.2.2 |

---

**Aloqa:** texnik savollar va integratsiya bo'yicha yordam uchun UzCORE bilan bog'laning.
*(Aloqa ma'lumotlari hujjat rasmiylashtirilganda kiritiladi.)*
