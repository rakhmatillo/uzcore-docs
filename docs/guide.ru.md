# Национальный SOC (UzCORE) — Техническое руководство по передаче данных

**Версия:** 1.0
**Дата:** 2026-09-28
**Статус:** Для рассылки организациям
**Стандарты:** OCSF 1.9.0 (Detection Finding 2004 + Incident Finding 2005) · ENISA RSIT 1.3 · таксономия EU NIS 2 · MITRE ATT&CK · CVE / CPE 2.3 · TLP 2.0 · O'zMSt 816:2025 · O'zMSt ISO/IEC 27005:2024 · O'z DSt 2814:2014 · ISO 8601 · RFC 4122 (UUID)

---

## 0. О документе

### 0.1 Передача данных

Приведённые ниже в данном документе образцы данных в формате JSON предназначены для передачи напрямую через API.


### 0.2 Типы передаваемых данных

UzCORE принимает от организаций данные следующих типов:

| # | Телеметрия | Система-источник | Режим передачи | Конфиденциальность |
|---|---|---|---|---|
| 1 | **Incident Report** — подтверждённый инцидент безопасности | SOAR / Case-management (TheHive, XSOAR, Sentinel, QRadar SOAR) | При открытии инцидента + при каждом значимом обновлении | По TLP, обычно AMBER |
| 2 | **Alert** — обнаружение одним средством | SIEM / EDR / IDS (Wazuh, Splunk, Elastic) | В реальном времени или пакетно (≤5 минут) | AMBER |
| 3 | **Asset Inventory** — перечень активов | SIEM / средство инвентаризации | Снапшот по интервалу (1 раз в сутки) | **TLP:RED** |


---

## 1. Общие технические правила

### 1.1 Транспорт и эндпоинты

Все запросы: `HTTPS`, `Content-Type: application/json`, кодировка `UTF-8`.

| Метод | Endpoint | Что делает |
|---|---|---|
| `GET` | `/connector/me` | Возвращает профиль организации аутентифицированного субъекта |
| `POST` | `/connector/bulk-incidents` | Передача пакета отчётов об инцидентах |
| `POST` | `/connector/bulk-alerts` | Передача пакета алертов |
| `POST` | `/connector/bulk-assets` | Передача снапшота активов |


### 1.2 Аутентификация — подпись HMAC-SHA256

Каждый запрос **подписывается локально секретным ключом**, а сам ключ никогда не покидает вашу сторону и не передаётся по сети.

#### 1.2.1 Регистрация организации

Связавшись с администрацией Центра кибербезопасности, вы получаете для своей организации два значения:

| Значение | Для чего |
|---|---|
| `organizationId` | Идентифицирует вашу организацию. Передаётся в каждом запросе через заголовок `x-org-id`. |
| `key` | Секретный ключ. **Никогда не отправляется на сервер** — остаётся только на вашей стороне и используется для локальной подписи запросов. |

#### 1.2.2 Хранение данных

`key` — секретные данные уровня пароля:

- Не записывается в код и не попадает в Git.
- Хранится в переменной окружения, secret manager или зашифрованном конфигурационном файле.
- При хранении в файле права доступа — `0600`.
- Не выводится в логи, сообщения об ошибках или trace.

При подозрении на утечку ключа необходимо незамедлительно обратиться в Центр кибербезопасности.

#### 1.2.3 Подпись запроса

Каждый запрос подписывается HMAC-SHA256.

| Header | Значение |
|---|---|
| `x-org-id` | `organizationId` |
| `x-timestamp` | Время запроса, epoch в секундах |
| `x-nonce` | Случайная строка для каждого запроса (защита от replay-атак) |
| `x-signature` | Результат HMAC-SHA256, hex в нижнем регистре |


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

#### 1.2.4 Проверка и запуск

**Перед** отправкой реальных данных подтвердите работоспособность интеграции:

```
GET /connector/me
```

Если подпись верна, сервер возвращает профиль вашей организации. Любой другой ответ означает ошибку в заголовках или в самой подписи.


### 1.3 `org_id` — место, где ошибаются чаще всего

В каждой записи есть **два идентификатора**, и они не обязаны совпадать:

| Место | Поле | Значение |
|---|---|---|
| HTTP header | `x-org-id` | **Кто отправил** — аутентифицированная организация. Обычно региональный SOC или MSSP. |
| Тело payload | `org_id` | **О ком** — организация, в которой произошёл инцидент или к которой относятся данные. |

Backend разделяет их следующим образом: подпись проверяется по `x-org-id`, а данные записываются на `org_id` из тела. **`sender_id` в теле не передаётся** — отправитель уже идентифицирован через заголовок и подпись.

Три сценария:

```
1. Организация отправляет сама:
   header  x-org-id = org-A
   тело    org_id   = org-A            ← оба одинаковы

2. Отраслевой SOC отправляет от имени участника:
   header  x-org-id = sector-soc-finance
   тело    org_id   = org-bank-014     ← различаются

3. MSSP отправляет от имени клиента:
   header  x-org-id = mssp-alpha
   тело    org_id   = org-clinic-007   ← различаются
```

**Отдельное требование для MSSP:** данные нескольких клиентов не смешиваются в одном payload. Для каждого `org_id` отправляется отдельный запрос. Смешанные (не поддающиеся атрибуции) данные отклоняются.

### 1.4 Форматы времени — ВНИМАНИЕ, их два

| Телеметрия | Формат | Пример |
|---|---|---|
| Incident Report | **ISO 8601**, UTC, с `Z` | `"2026-08-13T09:12:44Z"` |
| Asset Inventory | **ISO 8601**, UTC, с `Z` | `"2026-08-13T02:00:00Z"` |
| Alert — `collected_at` | **ISO 8601**, UTC | `"2026-08-13T09:15:00Z"` |
| Alert — внутренние поля OCSF (`time`, `start_time`, `end_time`, `metadata.logged_time`) | **epoch в миллисекундах** (integer) | `1786594364512` |

Конвертация:

```python
# ISO -> epoch ms
import datetime
dt = datetime.datetime(2026, 8, 13, 4, 12, 44, 512000, tzinfo=datetime.timezone.utc)
epoch_ms = int(dt.timestamp() * 1000)   # 1786594364512

# epoch ms -> ISO
datetime.datetime.fromtimestamp(1786594364512/1000, datetime.timezone.utc).isoformat()
```

### 1.5 Идемпотентность и генерация `report_id`

Если сеть оборвалась или ответ не пришёл, **повторно отправьте тот же самый payload**. 

| Телеметрия | Ключ идемпотентности |
|---|---|
| Incident | `report_id` |
| Alert | `org_id` + `metadata.product.name` + `finding_info.uid` |
| Asset | `org_id` + `asset_uid` (upsert, §4.2) |


#### 1.5.1 Детерминированный UUID v5

**`report_id` не хранится, он каждый раз вычисляется заново.** При одинаковых входных данных результат всегда одинаков.

UUID v5 (RFC 4122 §4.3) — детерминированный UUID на основе имени с использованием SHA-1.

```
report_id = uuidv5(UzCORE_NAMESPACE, org_id + "|" + source_case_id)
```

**Namespace UUID UzCORE (одинаковый для всех организаций, не меняется):**

```
17e9f2a9-2473-5a70-b622-f121ae871cb0
```

**Разобранный пример:**

```
org_id          = b3f1c2a4-1d2e-4f56-9abc-1234567890ab
source_case_id  = CASE-2026-0441
nom satri       = "b3f1c2a4-1d2e-4f56-9abc-1234567890ab|CASE-2026-0441"

report_id       = 8f339179-64ae-5763-99ab-2a0c6562203e
```

Другой кейс:

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


#### 1.5.2 Правила нормализации — обязательные

Детерминизм работает только тогда, когда входная строка совпадает **посимвольно**:

| Правило | Причина |
|---|---|
| `org_id` — приводится к нижнему регистру, пробелы удаляются | UUID иногда записываются в верхнем регистре |
| `source_case_id` — удаляются только пробелы, **регистр не меняется** | Case ID регистрозависимы (`CASE-441` ≠ `case-441`) |
| Разделитель — всегда `\|` (вертикальная черта) | `-` или `:` могут встречаться внутри case ID |

#### 1.5.3 Поэтому `source_case_id` — ОБЯЗАТЕЛЬНОЕ

В каждой SOAR/case-системе это значение есть:

| Система | Поле |
|---|---|
| TheHive | `case.caseId` или `case._id` |
| Cortex XSOAR | `incident.id` |
| Microsoft Sentinel | `incident.properties.incidentNumber` |
| Splunk SOAR | `container.id` |
| IBM QRadar SOAR | `incident.id` |
| ServiceNow SecOps | `sn_si_incident.number` |


### 1.6 Коды ответов и формат ошибок

UzCORE возвращает ошибки по стандарту **RFC 9457 (Problem Details for HTTP APIs)**.

Заголовок ответа: `Content-Type: application/problem+json`

**Стандартные поля (RFC 9457 §3.1):**

| Поле | Описание |
|---|---|
| `type` | URI, обозначающий тип проблемы. Для UzCORE: `https://uzcore.csec.uz/problems/<slug>` |
| `title` | Краткий человекочитаемый заголовок. Для одного и того же `type` не меняется. |
| `status` | HTTP-код статуса (совпадает с кодом ответа) |
| `detail` | Пояснение именно для данного случая |
| `instance` | URI, обозначающий данный конкретный запрос |

**Расширение UzCORE (extension member):** массив `errors[]` — отдельная ошибка для каждого поля. RFC 9457 §3.2 допускает поля-расширения.

Структура элемента массива соответствует стандартному формату вывода JSON Schema 2020-12:

| Поле | Описание |
|---|---|
| `pointer` | **RFC 6901 JSON Pointer** — точный адрес проблемного поля в payload |
| `code` | Машиночитаемый код ошибки |
| `detail` | Пояснение |
| `allowed` | При ошибках enum — список допустимых значений |

**Пример — `422`:**

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

**`pointer` для элемента внутри массива** включает индекс массива:

```json
{
  "pointer": "/assets/12/technical/known_cves/0/cve_id",
  "code": "format_invalid",
  "detail": "CVE identifikatori 'CVE-YYYY-NNNN+' formatida, katta harflarda bo'lishi kerak."
}
```

**Коды ошибок (`code`):**

| Код | Значение |
|---|---|
| `required` | Отсутствует обязательное поле |
| `enum_mismatch` | Значение отсутствует в списке допустимых |
| `type_mismatch` | Неверный тип данных (например, integer вместо string) |
| `format_invalid` | Нарушен формат (UUID, ISO 8601, CVE, CPE) |
| `out_of_range` | Число вне допустимого диапазона |
| `too_long` | Строка или массив длиннее предельного значения |
| `unknown_field` | Поле, отсутствующее в схеме (`additionalProperties: false`) |
| `conditional_required` | Отсутствует поле, ставшее обязательным из-за выполнения условия |
| `cross_field_conflict` | Поля противоречат друг другу (например, `detected_at` > `opened_at`) |
| `forbidden_field` | Поле, запрещённое к передаче (`metadata.tenant_uid`) |


### 1.7 TLP 2.0 — уровень конфиденциальности

Каждая запись несёт значение `tlp`. По этому значению UzCORE определяет, кто может видеть данные и как они распространяются.

| Значение | Значение | Когда используется |
|---|---|---|
| `CLEAR` | Распространяется без ограничений | Публичная информация |
| `GREEN` | Внутри сообщества | IOC, чтобы другие организации могли защититься |
| `AMBER` | Только организация и её клиенты | Стандартный случай — большинство инцидентов |
| `AMBER+STRICT` | Только внутри организации | Чувствительные инциденты |
| `RED` | Только поимённые получатели | Инвентаризация активов (обязательно) |

Для incident — `AMBER`, для asset inventory — `RED` (обязательно, другие значения не принимаются).

---

# 2. Incident Report — подтверждённый инцидент

## 2.1 Определение

Подтверждённый инцидент безопасности, по которому в SOAR / case-management системе организации **открыт кейс (case)**. Это не сигнал средства защиты — это инцидент, который аналитик рассмотрел, подтвердил как реальный и по которому начаты меры реагирования.

**Источник:** TheHive, Cortex XSOAR, Microsoft Sentinel, Splunk SOAR (Phantom), IBM QRadar SOAR, ServiceNow SecOps.

## 2.2 Когда отправляется

Один инцидент на протяжении своего жизненного цикла отправляется **несколько раз**, и каждый раз используется **один и тот же `report_id`**:

```
  Кейс открыт           →  status_id: 1 (New)
  Расследование начато  →  status_id: 2 (In Progress)
  Ожидание вендора      →  status_id: 3 (On Hold)
  Решён                 →  status_id: 4 (Resolved)
  Закрыт                →  status_id: 5 (Closed)  +  closed_at
```

Является ли это первой отправкой или обновлением — **отдельно не помечается**. Сервер определяет это сам по `report_id`: если он есть в базе — обновление, если нет — новый инцидент.

**Случаи, когда отправка обновления обязательна:**
- изменился `lifecycle.status_id`
- изменился `classification.severity_id`
- установлен или изменён `lifecycle.verdict_id`
- добавлен новый IOC или новый затронутый актив
- изменился `response.containment_status`

Для прочих мелких изменений отправлять обновление не требуется.

**Срок:** инциденты уровня `critical` и `high` отправляются **в течение 1 часа** после обнаружения, остальные — **в течение 24 часов**.

## 2.3 Полный пример JSON

Конверт несёт `org_id` один раз; инциденты — в массиве `incidents[]`. Ниже пакет с одним инцидентом:

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

## 2.4 Поля

### 2.4.1 Система обозначения полей

В каждой таблице полей есть столбец `R/O`:

| Обозначение | Значение |
|---|---|
| **R** | **Required** — обязательное. Без этого поля payload отклоняется с `422`. |
| **C** | **Conditional** — условно обязательное. Когда оно обязательно, указано в описании поля. |
| **O** | **Optional** — необязательное. Отправляется, если у организации есть эти данные. |
| **R\*** | Обязательное для каждого элемента **внутри** массива. Сам массив может быть необязательным. |
| **STD** | Значение берётся из **стандартного каталога** (OCSF, RSIT, MITRE, CVE). Не придумывается. Списки — в приложениях. |

### 2.4.2 Ссылки на стандарты

| Стандарт | Версия | Владелец | Где посмотреть |
|---|---|---|---|
| **OCSF** (Open Cybersecurity Schema Framework) | 1.9.0 | Linux Foundation | `https://schema.ocsf.io/1.9.0/` |
| **ENISA RSIT** (Reference Security Incident Taxonomy) | 1.3 | ENISA / TF-CSIRT | `https://github.com/enisaeu/Reference-Security-Incident-Taxonomy-Task-Force` |
| Таксономия воздействия **EU NIS 2** | — | NIS Cooperation Group | Для блока воздействия |
| **MITRE ATT&CK** | Enterprise v15+ | MITRE | `https://attack.mitre.org/` |
| **CVE** | — | MITRE / NVD | `https://nvd.nist.gov/` |
| **CPE** | 2.3 | NIST | `https://nvd.nist.gov/products/cpe` |
| **TLP** | 2.0 | FIRST | `https://www.first.org/tlp/` |


### 2.4.3 Конверт (envelope) — кто и когда

Эти поля относятся **ко всему пакету** и записываются один раз. Backend проверяет делегирование именно по этому `org_id` — независимо от того, сколько сотен инцидентов в массиве, проверка одна.

| Поле | Тип | R/O | Описание и допустимые значения |
|---|---|---|---|
| `telemetry_type` | string | **R** | Фиксированное значение: `"incident_batch"`. Направляет payload в нужный конвейер. |
| `schema_version` | string | **R** | Версия данного документа. Сейчас: `"1.0"`. |
| `org_id` | UUID | **R** | Организация, в которой произошли инциденты — **владелец данных** (§1.3). В одном запросе одна организация. |
| `collected_at` | timestamp | **O** | Время формирования пакета интеграцией. **ISO 8601 UTC.** Диагностическое поле — см. пояснение ниже. |
| `incidents` | array | **R** | 1–200 объектов incident |

**Зачем нужен `collected_at` и как он используется:**

Это поле несёт информацию не об инциденте, а **об интеграции**. У него две практические задачи:

| Задача | Как вычисляется | Что показывает |
|---|---|---|
| Задержка доставки | `collected_at − lifecycle.updated_at` | Сколько времени прошло с момента обновления кейса в SOAR до его поступления в UzCORE. Большая разница означает, что коннектор замедлился или застрял в очереди. |
| Признак живости интеграции | Последнее значение `collected_at` | Показывает, когда интеграция организации работала в последний раз — даже в дни без инцидентов. |

Если поле не заполнено, UzCORE использует время приёма запроса. Это тоже работает, но с меньшей точностью: оно включает сетевую задержку и очередь сервера, то есть отличить проблему коннектора от проблемы сети невозможно.

### 2.4.4 Элемент `incidents[]` — идентификация

| Поле | Тип | R/O | Описание и допустимые значения |
|---|---|---|---|
| `report_id` | UUID v5 | **R\*** | Стабильный идентификатор инцидента. **Вычисляется по формуле §1.5**, не генерируется случайно. Не меняется на протяжении жизненного цикла инцидента. |
| `source_case_id` | string | **R\*** | Собственный номер кейса организации. **Из него вычисляется `report_id` (§1.5), поэтому поле обязательно.** Не меняется на протяжении жизненного цикла инцидента. |
| `source_system` | string | **O** | Название системы кейсов: `"TheHive"`, `"XSOAR"`, `"Sentinel"`, `"Splunk SOAR"`, `"QRadar SOAR"`, `"Updive"`. |
| `tlp` | enum | **R\*** | `CLEAR` │ `GREEN` │ `AMBER` │ `AMBER+STRICT` │ `RED`. Обычное значение: `AMBER`. |
| `related_report_ids` | array[UUID] | **O** | `report_id` **других инцидентов, которые аналитик считает связанными** с данным. Подробнее: ниже. |
| `alerts` | array[string] | **O** | Значения `finding_info.uid` алертов, привязанных к данному инциденту. Расположение: **в самом** элементе `incidents[]`, на одном уровне с блоками `lifecycle` и `technical`. Связывает с телеметрией алертов и раскрывает цепочку CVE. |

**`related_report_ids` — когда используется:**

Это поле заполняется **только** когда аналитик считает два отдельных кейса связанными между собой. Типичные случаи:

- одна атака открыта в двух кейсах (дубликат), один объединён с другим
- несколько этапов одной кампании наблюдались в отдельных кейсах
- новый инцидент возник из-за того, что предыдущий не был полностью закрыт

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

В этом примере `verdict_id: 10` (Duplicate) говорит, что инцидент является дубликатом, а `related_report_ids` — дубликатом **какого** инцидента. Они работают вместе: UzCORE исключает дубликат из национальной статистики, но сохраняет связь.

### 2.4.5 `lifecycle` — жизненный цикл инцидента и скорость реагирования

| Поле | Тип | R/O | Описание и допустимые значения |
|---|---|---|---|
| `detected_at` | timestamp | **R\*** | Время, когда средство защиты организации **впервые обнаружило** активность — не время открытия кейса. Обычно время самого раннего алерта. Начальная точка всех расчётов `time_to_*`. |
| `opened_at` | timestamp | **R\*** | Время открытия кейса в SOAR. `opened_at − detected_at` = задержка триажа. |
| `updated_at` | timestamp | **R\*** | Время формирования именно этой версии отчёта. Меняется при каждом обновлении. |
| `closed_at` | timestamp | **C** | Время закрытия кейса. **Обязательно при `status_id` = `5`.** Иначе `null`. |
| `time_to_acknowledge_sec` | integer | **O** | MTTA: от `detected_at` до первого действия аналитика, в секундах. |
| `time_to_contain_sec` | integer | **O** | MTTC: от `detected_at` до локализации, в секундах. |
| `time_to_resolve_sec` | integer | **O** | MTTR: от `detected_at` до полного разрешения, в секундах. |
| `verdict_id` | integer | **O · STD** | Заключение по итогам расследования. Полный список и mapping: **Приложение B.6**. |

> Кейс всегда находится в одном из этих пяти состояний. Если состояние исходной системы отсутствует в списке, выберите ближайшее подходящее из таблицы **Приложения B.5**.

**`time_to_*_sec` — правило расчёта:**

Все три значения отсчитываются **от `detected_at`**, а не от `opened_at`. Это правило обязательно: если организации используют разные начальные точки, национальный показатель MTTR становится несопоставимым.

```
time_to_acknowledge_sec = birinchi_analitik_harakati − detected_at
time_to_contain_sec     = lokalizatsiya_vaqti      − detected_at
time_to_resolve_sec     = hal_qilingan_vaqt        − detected_at
```

Значения заполняются на основе данных SOAR. Если система не даёт нужного времени, оставьте поле `null` — не отправляйте приблизительное значение.

### 2.4.6 `classification` — тип инцидента (ENISA RSIT)

| Поле | Тип | R/O | Описание и допустимые значения |
|---|---|---|---|
| `event_category` | enum | **R\* · STD** | Первый уровень RSIT — 10 значений. Полный список: **Приложение A**. |
| `event_type` | enum | **O · STD** | Второй уровень RSIT. **Должен соответствовать выбранной категории.** Полный список: **Приложение A**. |
| `title` | string | **R\*** | Краткий заголовок, 3–120 символов. Конфиденциальная информация не указывается. |
| `description` | string | **O** | Очищенное резюме, ≤2000 символов. IP, имена пользователей, командные строки, сырые логи не включаются. |
| `severity_id` | integer | **R\* · STD** | `0` Unknown · `1` Informational · `2` Low · `3` Medium · `4` High · `5` Critical · `99` Other. **Та же шкала, что и в телеметрии алертов.** |

> **Почему `event_type` необязателен:** ни в одной SOAR-системе нет таксономии RSIT, то есть это значение всегда выбирается вручную. Лучше оставить поле пустым, чем выбрать неверный из 35 типов — картина на уровне категорий в национальной статистике всё равно останется верной.

### 2.4.7 `technical` — поведение атакующего

| Поле | Тип | R/O | Описание и допустимые значения |
|---|---|---|---|
| `mitre_attacks` | array[object] | **O · STD** | Тактики MITRE ATT&CK, под каждой — техники, под ними — субтехники. Структура ниже. |
| `affected_asset_uids` | array[string] | **O** | Значения `asset_uid` затронутых активов. Должны быть записаны точно так же, как `assets[].asset_uid` в инвентаризации активов. Это поле — единственный способ связи с активами. Заполняется, когда активы известны. Если ни один внутренний актив не задействован или масштаб ещё не определён, отправляется `[]` и заполняется при следующем обновлении lifecycle. |
| `indicators` | array[object] | **R\*** | IOC. Структура ниже. Пустой массив (`[]`) допускается только в том случае, если в исходной системе нет ни одного observable. |

#### `affected_asset_uids` — hostname, а не ID актива в SOAR

SOAR-системы хранят затронутый актив под своим внутренним ID записи (например, FortiSOAR asset ID `a3f9…`). Этот ID в UzCORE **не отправляется**: в UzCORE такого актива нет, и связь теряется. Вместо него берётся атрибут **hostname** актива SOAR и нормализуется по следующему правилу.

**Правило нормализации** — одинаковое для `asset_uid` технического актива, `device.hostname` в алерте и `affected_asset_uids` в инциденте:

1. Удаляются пробелы в начале и в конце.
2. Приводится к нижнему регистру.
3. Если это FQDN, берётся часть до первой точки: `WEB01.corp.local` → `web01`.
4. IP-адрес не записывается в качестве hostname.

**Где в SOAR находится hostname:**

| SOAR | Где находится затронутый актив | Откуда берётся hostname |
|---|---|---|
| TheHive | Observable | `dataType: hostname` |
| Cortex XSOAR | Incident field / indicator | `Hostname`, `Device Name` |
| Microsoft Sentinel | Entity `Host` | `HostName` (`DnsDomain` не добавляется) |
| Splunk SOAR | Artifact (CEF) | `destinationHostName`, `deviceHostname` |
| IBM QRadar SOAR | Artifact | `System Name` |
| FortiSOAR | Запись модуля Assets | поле `hostname` |

Если в SOAR у актива есть только IP-адрес, он в `affected_asset_uids` не записывается — связь восстанавливается через `alerts[]`.

> **Защита на стороне UzCORE.** UzCORE ищет пришедшее значение в двух местах: `asset_uid` актива и нормализованный `technical.hostname`. Кроме того, если `affected_asset_uids` пуст или не совпадает, актив находится через `alerts[]` → `device.hostname` в алерте. Поэтому важно записывать в `alerts[]` ID алертов SIEM, относящихся к инциденту.

**Элемент `indicators[]`:**

| Поле | Тип | R/O | Описание и допустимые значения |
|---|---|---|---|
| `type` | enum | **R\*** | `ipv4` │ `ipv6` │ `domain` │ `url` │ `md5` │ `sha1` │ `sha256` │ `email` │ `file_name` │ `user_agent` │ `registry_key` |
| `value` | string | **R\*** | Значение индикатора. Выполняется refang, домены и хэши записываются в нижнем регистре, внутренние адреса RFC 1918 не отправляются. |

> Индикатор состоит только из двух полей: **тип и значение**. `role`, `tlp` и `first_seen` отсутствуют намеренно — первое не существует ни в одном SOAR и приходило бы пустым, второе покрывается `tlp` инцидента, третье дублирует `lifecycle.detected_at`.

**`mitre_attacks[]` — трёхуровневая структура:**

```
mitre_attacks[]
 └── tactic                    (одна тактика, обязательно)
 └── techniques[]              (техники этой тактики, минимум одна)
      └── sub_techniques[]     (подтехники этой техники, необязательно)
```

| Поле | Тип | R/O | Описание и допустимые значения |
|---|---|---|---|
| `tactic` | object | **R\*** | Тактика. **Обязательное** — техника без тактики не отправляется. |
| `tactic.uid` | string | **R\* · STD** | Формат: `TA####`. Пример: `"TA0006"`. Полный список: **Приложение B.9** |
| `tactic.name` | string | **O** | `"Credential Access"` |
| `techniques` | array | **R\*** | Техники под данной тактикой. **Минимум одна**, пустой массив отклоняется. |
| `techniques[].uid` | string | **R\* · STD** | Формат: `T####`. Пример: `"T1110"`. Субтехника сюда не записывается. |
| `techniques[].name` | string | **O** | `"Brute Force"` |
| `techniques[].sub_techniques` | array | **O** | Субтехники. При отсутствии поле не записывается вообще. |
| `…sub_techniques[].uid` | string | **R\* · STD** | Формат: `T####.###`. Пример: `"T1110.001"` |
| `…sub_techniques[].name` | string | **O** | `"Password Guessing"` |

**Обязательные правила:**

- **Одна тактика встречается один раз.** Если под одной тактикой несколько техник, они перечисляются внутри `techniques[]` — тактика не повторяется.
- **Субтехника без родительской техники не отправляется.** Если исходная система даёт только `T1110.001`, коннектор или разработчик, отправляющий напрямую через API, выводит родительскую технику из самого ID (`T1110`) и записывает её в `techniques[].uid`, а субтехнику помещает в её `sub_techniques[]`.
- **Тактика обязательна.** Если в исходной системе тактики нет, её нужно определить по каталогу ATT&CK. Если одна техника относится к нескольким тактикам, аналитик выбирает, с какой целью она использовалась в инциденте.
- **Дублирование запрещено.** Если один и тот же `tactic.uid`, один и тот же `techniques[].uid` или один и тот же `sub_techniques[].uid` записан дважды, payload отклоняется.

**Пример — три техники под одной тактикой, одна из них с двумя субтехниками:**

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

> **Почему тактика обязательна?** Тактика **не выводится** из техники — одна техника может относиться к нескольким тактикам. Например, `T1078 Valid Accounts` встречается в четырёх тактиках: Initial Access, Persistence, Privilege Escalation, Defense Evasion. Если отправлен только ID техники, невозможно понять, проникал ли атакующий, закреплялся или повышал привилегии.
>
> Поэтому нормально и то, что одна техника встречается **под несколькими тактиками**: если атакующий использовал `T1078` сначала для проникновения, затем для закрепления, она записывается в обеих группах — `TA0001` и `TA0003`.

> **Отличие от алерта:** в телеметрии алертов эта информация по требованию OCSF хранится в `finding_info.attacks[]` в виде **плоских** пар (`{tactic, technique, sub_technique}`). Структуру полей OCSF изменять нельзя. В инциденте же используется вложенная форма — она точнее передаёт полную картину, записанную аналитиком. Коннектор формирует обе формы.

> **`kill_chain_phase` отсутствует.** Поле kill-chain Lockheed Martin в этом документе **не используется вообще** — ни в инциденте, ни в алерте. Тактики ATT&CK отвечают на тот же вопрос точнее (14 тактик вместо 7 этапов), а хранение обоих полей вместе приводит к противоречиям — например, `kill_chain_phase: "delivery"` рядом с `tactic: TA0040 Impact`. Этап атаки выражается через `mitre_attacks[].tactic`. Полный список тактик: **Приложение B.9**.
>
### 2.4.8 `response` — что было сделано

| Поле | Тип | R/O | Описание и допустимые значения |
|---|---|---|---|
| `actions_taken` | array[string] | **O** | Действия, выполненные в рамках кейса, свободный текст. Каждое ≤300 символов. |
| `containment_status` | enum | **O · STD** | Этап реагирования: `not_contained` │ `partially_contained` │ `contained` │ `eradicated` │ `recovered` |
| `closing_note` | string | **O** | Свободный комментарий при закрытии кейса, ≤2000 символов. |

> **В `actions_taken` и `closing_note` конфиденциальная информация не записывается.** Имя хоста, IP-адрес, логин пользователя, имя сотрудника, командная строка — ничего из этого. Правильно: `"Заражённый хост изолирован"`. Неправильно: `"web014 (10.0.2.14) изолирован, учётная запись root заблокирована"`.

**`containment_status` — этапы реагирования по NIST SP 800-61:**

| Значение | Смысл |
|---|---|
| `not_contained` | Не локализовано, атака продолжается |
| `partially_contained` | Частично локализовано, некоторые векторы открыты |
| `contained` | Локализовано, распространение остановлено |
| `eradicated` | Вредоносный компонент удалён из системы |
| `recovered` | Система вернулась к нормальной работе |

Это поле **не дублирует** `lifecycle.status_id`: `status_id` отражает рабочий процесс (кто работает), а `containment_status` — техническое состояние (остановлена ли атака). Инцидент со `status_id: 2` (In Progress) может быть как локализованным, так и нет — и самое срочное представление для оператора — это именно пересечение этих двух: **критичный + не локализован**.

**`closing_note` — не причина закрытия.** Причина закрытия записывается в структурированном виде в `lifecycle.verdict_id` (Приложение B.6). `closing_note` же — свободный комментарий рядом с ней: что было сделано, что было выявлено.

### 2.4.9 `activity` — хронология кейса

Все шаги, выполненные по кейсу, в хронологическом порядке: открытие, изменения статуса, комментарии, задачи, закрытие и повторное открытие. Эти данные показывают, как велась работа по инциденту — национальный оператор, рассматривая серьёзный инцидент, именно по ним узнаёт, что сделала организация.

> **Список задач отдельно не отправляется.** Полный список задач внутри кейса (заголовок, ответственный, статус) в UzCORE не передаётся. В хронологии же сохраняются события `task_created` и `task_completed` — то есть виден **факт и время** постановки и выполнения задачи, но не её содержание. Этого достаточно для измерения темпа реагирования и не создаёт риска для конфиденциальности.

| Поле | Тип | R/O | Описание и допустимые значения |
|---|---|---|---|
| `time` | timestamp | **R\*** | Время события (ISO 8601 UTC) |
| `type` | enum | **R\*** | Тип события — таблица ниже |
| `to_status_id` | integer | **C** | Новый статус. **Обязательное при `type` = `status_changed`.** |
| `to_severity_id` | integer | **C** | Новая критичность. **Обязательное при `type` = `severity_changed`.** |

**Значения `type`:**

| Значение | Когда записывается | Дополнительное поле |
|---|---|---|
| `case_opened` | Кейс открыт | — |
| `case_closed` | Кейс закрыт | — |
| `case_reopened` | Закрытый кейс открыт повторно | — |
| `status_changed` | Статус изменён | `to_status_id` |
| `comment_added` | Добавлен комментарий | — |
| `task_created` | Поставлена задача | — |
| `task_completed` | Задача выполнена | — |
| `severity_changed` | Критичность переоценена | `to_severity_id` |
| `artifact_added` | Добавлен новый IOC или улика | — |
| `other` | Не соответствует вышеперечисленному | — |

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

> ## Текст комментария НЕ ОТПРАВЛЯЕТСЯ
>
> `comment_added` означает только **факт и время добавления комментария** — не сам текст.

**Отправляется полная история.** При каждом обновлении повторно отправляется вся хронология, а не только новые записи.

**Откуда берётся в исходных системах:**

| Система | Источник |
|---|---|
| TheHive | `Case Logs`, `Task Logs`, audit trail |
| Cortex XSOAR | Записи `War Room`, `Incident Audit Trail` |
| Microsoft Sentinel | `Comments` + изменения статуса в таблице `SecurityIncident` |
| Splunk SOAR | Container audit, `Notes` |
| IBM QRadar SOAR | Incident timeline |
| ServiceNow SIR | `Activity Stream`, `Work Notes` |
| Updive | Поток активности кейса |

> **`case_reopened` имеет особое значение.** Повторное открытие закрытого инцидента означает, что инцидент был решён плохо. Это сигнал качества, видимый на национальном уровне, и сам по себе `status_id` его не показывает: он просто возвращается с `5` на `2`, и без истории это незаметно.

## 2.5 Минимальный пример — с наименьшим числом полей

Если у организации нет полной информации, принимается следующий payload:

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

## 2.6 Пример закрытия

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

## 2.7 Частые ошибки

| Ошибка | Последствие | Правильное решение |
|---|---|---|
| Новый `report_id` при каждом обновлении | Один инцидент выглядит в национальной статистике как 5 | Использовать формулу из §1.5 |
| `event_type` не соответствует категории | Ошибка `422` | Проверить по таблице Приложения A |
| `org_id` внутри элемента incident | Ошибка `422` — он относится к конверту | Один раз в конверте |
| Собственный `report_id` внутри `related_report_ids` | Ошибка `422` | Это поле ссылается только на ДРУГИЕ инциденты |
| Несколько организаций в одном запросе | Ошибка `422` | Отдельный запрос для каждого `org_id` |
| Статус исходной системы отправлен напрямую (`"Active"`, `"Done"`) | Ошибка `422` | Преобразовать в `status_id` по таблице маппинга Приложения B.5 |
| В `status_id` вложен смысл `contained` | Смешиваются рабочий процесс и этап реагирования | Локализация выражается в `containment_status` |
| `detected_at` = `opened_at` | Интервал обнаружение–реагирование выглядит как 0, показатель MTTA искажается | Брать реальное время обнаружения инструментом |
| `affected_asset_uids` пуст, хотя активы известны | Инцидент не привязывается ни к одному активу, теряется большая часть корреляции | Заполняется, когда активы известны. Если ни один внутренний актив не задействован или масштаб ещё не определён, отправляется `[]` и заполняется при следующем обновлении lifecycle. |
| В `indicators` включены внутренние IP | Ложные совпадения с другими организациями, ложный сигнал «кампании» | Фильтровать адреса RFC 1918 |
| Запись сырого лога в `description` | Утечка конфиденциальной информации | Записывать только очищенное резюме |
| Запись имени хоста/IP в `actions_taken` или `closing_note` | Информация TLP:RED просачивается в инцидент AMBER | Обобщённая формулировка: «Заражённый хост изолирован» |
| В `activity` отправлен текст комментария | Ошибка `422` — в схеме нет такого поля | Отправляются только `time` и `type` |
| В `activity` только последние новые записи | Хронология прерывается | Полная история при каждом обновлении |
| В `status_id` отправлено `0` или `99` | Ошибка `422` | Только `1`–`5`; выбрать ближайшее соответствие из Приложения B.5 |
| Локальное время (без `+05:00`) | Все трендовые графики смещаются на 5 часов | Перевести в UTC, добавить `Z` |

---

# 3. Алерт — OCSF Detection Finding

## 3.1 Определение и отличие от инцидента

Алерт — **одно обнаружение, созданное одним средством защиты**. Он представляется классом **Detection Finding** стандарта OCSF 1.9.0 (`class_uid = 2004`, `category_uid = 2 Findings`).


**Важно:** в алерте `activity_id` **всегда `1` (Create)**. Алерт — неизменяемый факт обнаружения. Если его состояние меняется (закрыт, признан false positive) — это отражается в телеметрии инцидентов, а не в алерте. В противном случае коннектору пришлось бы на каждом цикле пересканировать всю базу алертов.

## 3.2 Формат отправки — конверт

Тело запроса — **конверт (envelope)**: идентификация организации указывается один раз сверху, а алерты — в массиве `alerts[]`.

```json
{
  "telemetry_type": "alert_batch",
  "schema_version": "1.0",
  "org_id": "b3f1c2a4-1d2e-4f56-9abc-1234567890ab",
  "collected_at": "2026-08-13T04:15:00Z",
  "alerts": [ /* OCSF Detection Finding obyektlari */ ]
}
```

| Поле | Тип | R/O | Описание |
|---|---|---|---|
| `telemetry_type` | string | **R** | Фиксированное значение: `"alert_batch"` |
| `schema_version` | string | **R** | `"1.0"` |
| `org_id` | UUID | **R** | Организация, которой принадлежат алерты — **владелец данных** (§1.3). В одном запросе — одна организация. |
| `collected_at` | timestamp | **R** | Время сбора пакета интеграцией. **ISO 8601 UTC.** |
| `alerts` | array | **R** | 1–500 объектов OCSF Detection Finding |

- В одном запросе — **один `org_id`**. MSSP отправляет отдельный запрос для каждого клиента.
- Для отправки одного алерта также используется конверт: `"alerts": [ { ... } ]`.
- **Внутри** элементов алерта **нет `org_id` или `collected_at`** — они находятся в конверте.

> `collected_at` (ISO 8601) и `time` внутри алерта (epoch ms) присутствуют оба, и это **не ошибка**: `time` — время обнаружения средством защиты, `collected_at` — время получения его интеграцией. Разница показывает задержку доставки.

## 3.3 Полный пример JSON — один алерт

Ниже полностью показан один элемент массива `alerts[]` (конверт — в §3.2):

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

## 3.4 Поля

### 3.4.1 Классификация OCSF — фиксированные (const) значения

Эти четыре поля **всегда одинаковы**. При отправке другого значения payload отклоняется.

| Поле | Тип | R/O | Значение | Почему |
|---|---|---|---|---|
| `class_uid` | integer | **R · STD** | `2004` | Класс OCSF Detection Finding |
| `category_uid` | integer | **R · STD** | `2` | Категория OCSF Findings |
| `activity_id` | integer | **R · STD** | `1` | Create. Алерт неизменяем — других значений нет |
| `type_uid` | integer | **R · STD** | `200401` | `class_uid × 100 + activity_id` |

**Текстовые названия в OCSF — для справки, не отправляются:**

| Поле | Значение | Текст OCSF |
|---|---|---|
| `class_uid` | `2004` | Detection Finding |
| `category_uid` | `2` | Findings |
| `activity_id` | `1` | Create |
| `type_uid` | `200401` | Detection Finding: Create |

### 3.4.2 Поля времени — все в epoch-миллисекундах

| Поле | Тип | R/O | Описание |
|---|---|---|---|
| `time` | integer | **R** | Время срабатывания обнаружения, **epoch ms**. |
| `start_time` | integer | **O** | Время начала наблюдаемой активности. |
| `end_time` | integer | **O** | Время окончания наблюдаемой активности. |

> **`start_time` и `end_time` — пара.** Если отправляется `end_time`, то `start_time` также обязателен и должно выполняться условие `start_time ≤ end_time`. Иначе `422`. В агрегированных обнаружениях (например, 500 попыток за 10 минут) это окно вместе с `count` показывает интенсивность атаки.

### 3.4.3 Критичность, состояние, агрегация

| Поле | Тип | R/O | Допустимые значения |
|---|---|---|---|
| `severity_id` | integer | **R · STD** | `0` Unknown · `1` Informational · `2` Low · `3` Medium · `4` High · `5` Critical · `99` Other |
| `status_id` | integer | **O · STD** | Состояние триажа алерта: `0` Unknown · `1` New · `2` In Progress · `3` Suppressed · `4` Resolved · `5` Archived · `99` Other. Маппинг: **Приложение B.2**. |
| `count` | integer | **O** | Количество событий, агрегированных источником в это одно обнаружение (например, Wazuh `rule.firedtimes`) |

> **`severity_id` — НЕ диапазон.** Принимаются только `{0, 1, 2, 3, 4, 5, 99}`. `7`, `50`, `12` — неверно.
> **`severity_id = 0`** используется **честно** в случае, когда исходная система не задала уровень критичности. Не выдумывайте его.

> **`status_id` и обновление алерта.** При изменении состояния алерта (например, когда он стал `Suppressed`) его можно отправить повторно с **тем же** `finding_info.uid` — запись перезаписывается. Ключ идемпотентности: `org_id` + `metadata.product.name` + `finding_info.uid`. В системах без состояния, таких как Wazuh, это поле остаётся пустым.

**Маппинг из исходных систем в `severity_id`:**

| Значение источника | `severity_id` |
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

> **В Suricata и Snort порядок обратный:** `1` — наивысшая критичность, `4` — наименьшая. При прямом копировании критические алерты превратятся в `Low`.

**Для систем, выдающих только числовую оценку (шкала 0–100):**

| Диапазон | `severity_id` |
|---|---|
| 0–19 | `1` Informational |
| 20–39 | `2` Low |
| 40–59 | `3` Medium |
| 60–79 | `4` High |
| 80–100 | `5` Critical |

### 3.4.4 `metadata` — об исходной системе

| Поле | Тип | R/O | Описание |
|---|---|---|---|
| `metadata.version` | string | **R · STD** | Фиксированное: `"1.9.0"` — версия схемы OCSF |
| `metadata.product.name` | string | **R** | Название средства: `"Wazuh"`, `"CrowdStrike Falcon"`, `"Microsoft Defender"` |
| `metadata.product.version` | string | **O** | Версия средства |
| `metadata.event_code` | string | **O** | ID сработавшего правила/сигнатуры (Wazuh `rule.id`, Sigma rule id) |
| `metadata.event_name` | string | **O** | Пара к `event_code` — название сработавшего правила/сигнатуры (Wazuh `rule.description`, Suricata signature), ≤300 символов. Расширение UzCORE: в OCSF `metadata` такого атрибута нет. |
| `metadata.logged_time` | integer | **O** | Время поступления лога в систему (epoch ms) |


### 3.4.5 `finding_info` — само обнаружение

| Поле | Тип | R/O | Описание |
|---|---|---|---|
| `finding_info.uid` | string | **R** | **Собственный ID исходного средства для этого обнаружения.** Должен быть стабильным — ключ идемпотентности и точка связи с `alerts[]` в инциденте. |
| `finding_info.title` | string | **R** | **Название правила**, ≤300 символов. НЕ текст события: `"SSH brute-force detected"` — верно, `"Failed login for user admin from 10.0.2.14"` — неверно (значения относятся к `observables`). |
| `finding_info.attacks[]` | array | **O · STD** | MITRE ATT&CK. В каждом элементе должен быть **как минимум один** из `technique`, `sub_technique` или `tactic`. |

**Элемент `attacks[]`:**

```json
{
  "technique":     { "uid": "T1110" },
  "sub_technique": { "uid": "T1110.001" },
  "tactic":        { "uid": "TA0006" }
}
```

Значения `uid` берутся **из каталога MITRE**: техника `T####`, подтехника `T####.###`, тактика `TA####`. Название не указывается — только ID.

**Если исходная система даёт только название** (например, Wazuh `rule.mitre.tactic` = `"Credential Access"`), разработчик находит ID по названию и отправляет его: полный список тактик — в **Приложении B.9**, техники — на `https://attack.mitre.org/`.

### 3.4.6 `device` — затронутое устройство

| Поле | Тип | R/O | Описание |
|---|---|---|---|
| `device.hostname` | string | **R** | **Ключ связи с инвентаризацией активов.** В нормализованном виде должен совпадать с `assets[].asset_uid` (правило: §2.4.7). |
| `device.ip` | string | **O** | IP-адрес |
| `device.mac` | string | **O** | MAC-адрес, **в нижнем регистре**: `00:1a:2b:3c:4d:5e`. Сопоставляется с `technical.mac_addresses[]` актива. |

### 3.4.7 `observables` — индикаторы

| Поле | Тип | R/O | Описание |
|---|---|---|---|
| `observables[].type_id` | integer | **R\* · STD** | Таблица ниже |
| `observables[].value` | string | **R\*** | Значение. Внешние значения подвергаются refang, домены и хеши записываются в нижнем регистре. |

> **Внутренние значения тоже отправляются.** В отличие от `indicators[]` (инцидент), в `observables[]` попадают **все** значения, встреченные в алерте — включая имя хоста жертвы и внутренний IP. Причина: они нужны для привязки к активу, то есть формируют список «алерты на этом активе». При поиске межорганизационных кампаний UzCORE учитывает только внешние значения.

**Допустимые значения `type_id`:**

| ID | Название | Пример |
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


### 3.4.8 `vulnerabilities` — уязвимости

| Поле | Тип | R/O | Описание |
|---|---|---|---|
| `vulnerabilities[].cve.uid` | string | **R\* · STD** | Идентификатор CVE в формате `CVE-YYYY-NNNN+` |
| `vulnerabilities[].severity` | string | **O** | Критичность уязвимости в том виде, как её указала исходная система: `"Critical"`, `"High"`, `"Medium"`, `"Low"` |

## 3.5 Минимальный пример алерта

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


## 3.6 Частые ошибки

| Ошибка | Последствие | Правильное решение |
|---|---|---|
| `os.type_id: 201` для Linux | Весь парк Linux выглядит как Android | Linux = `200` |
| `time` отправлен в секундах | Дата попадает в 1970 год | Миллисекунды: `× 1000` |
| `severity_id: 12` | Ошибка `422` | Только `{0,1,2,3,4,5,99}` |
| `org_id` внутри элемента алерта | Ошибка `422` — он относится к конверту | Один раз в конверте |
| Тело запроса — массив (`[...]`) | Ошибка `400` | Объект-конверт: `{ "alerts": [...] }` |

---

# 4. Asset Inventory — инвентаризация активов

## 4.1 Определение и конфиденциальность

Перечень активов организации. Активы делятся на две группы:

| Группа | Классы | Типичный источник |
|---|---|---|
| **Технические активы** | `hardware`, `software`, `network`, `service`, `information_resource`, `security_tool` | SIEM / EDR / сканер уязвимостей — автоматически |
| **Реестровые активы** | `information`, `process`, `personnel`, `site`, `organization`, `intangible` | Вручную организацией или из системы CMDB/GRC (реестр информационных активов, ведущийся согласно приложению L O'zMSt 816:2025) |

Таксономия — 12 классов и 70 типов — построена на основе **O'zMSt 816:2025** (§7.9.2 объекты защиты) и расширена с учётом O'zMSt ISO/IEC 27005:2024, ISO/IEC 27001:2022 Annex A и ПҚ-167 (полный перечень: **Приложение E**). Какие классы отправлять, организация решает сама: всё отправленное принимается.

> ## ⚠️ КОНФИДЕНЦИАЛЬНОСТЬ — TLP:RED
>
> Эта телеметрия содержит **hostname, IP-адреса, открытые порты и уязвимости**.
>
> **Обязательные меры на стороне организации:** отправка только по TLS 1.2+, в поле `tlp` — только `RED`.
>
> В классе `personnel` **имя, логин, email, телефон нигде не указываются**, в том числе в `asset_uid`. `asset_uid` должен быть анонимным: `role-ciso`, `user-0417`.

## 4.2 Режим отправки — upsert

UzCORE принимает активы по принципу **upsert**: поступивший актив записывается в базу либо обновляется существующая запись. Неотправленный актив **не удаляется** — он остаётся в базе, просто его значение `last_seen` не обновляется.

Поэтому технические и реестровые активы можно отправлять **раздельно и в разном ритме**: SIEM ежедневно отправляет технические активы, а реестр, заполняемый вручную, отправляется при изменении. Они не мешают друг другу.

| Правило | Подробности |
|---|---|
| **Интервал** | Технические активы — раз в сутки (рекомендация: ночью). Реестровые активы — при изменении. |
| **Удаление актива** | Только явным сигналом: отправляется `lifecycle_status: "decommissioned"`. Отсутствие в списке ничего не означает. |
| **Устаревший актив** | Актив, у которого `last_seen` давно не обновлялся, помечается как «устаревший» — **только для активов с `provenance: "discovered"`**. Введённые вручную (`declared`) активы отправляются редко, к ним это правило не применяется. |
| **Идемпотентность** | Благодаря upsert повторная отправка одного и того же снимка не создаёт дублирующих записей — актив идентифицируется по `org_id` + `asset_uid`. |

## 4.3 Полный пример JSON

Один технический актив (из SIEM) и один реестровый актив (введённый вручную):

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

## 4.4 Поля

### 4.4.1 Конверт

| Поле | Тип | R/O | Определение и допустимые значения |
|---|---|---|---|
| `telemetry_type` | string | **R** | Строго: `"asset_inventory"` |
| `schema_version` | string | **R** | `"1.0"` |
| `org_id` | UUID | **R** | Организация, которой принадлежат активы — владелец данных (§1.3) |
| `tlp` | enum | **R** | Всегда `"RED"`. Другое значение отклоняется. |
| `source_system` | string | **O** | Средство, предоставившее данные: `"Wazuh"`, `"Splunk"`, `"Tenable"`, `"CMDB"` |
| `collected_at` | timestamp | **R** | Время получения данных (ISO 8601 UTC) |
| `summary` | object | **R** | Быстрые показатели (§4.4.2) |
| `assets` | array | **R** | Перечень активов |

### 4.4.2 `summary` — быстрые показатели

Эти блоки сразу отображаются на дашборде и вычисляются без полного чтения массива `assets[]`.

| Поле | Тип | R/O | Определение |
|---|---|---|---|
| `summary.total_assets` | integer | **R** | Общее количество устройств. **Знаменатель всех нормализованных показателей** — например «сколько инцидентов на 100 активов». |
| `summary.servers` | integer | **O** | Количество серверов |
| `summary.endpoints` | integer | **O** | Количество рабочих станций и ноутбуков |
| `summary.network_devices` | integer | **O** | Количество маршрутизаторов, коммутаторов, межсетевых экранов |
| `summary.ot_ics_devices` | integer | **O** | Устройства операционных технологий / промышленных систем управления |
| `summary.internet_facing` | integer | **O** | Активы, видимые из интернета — **основной показатель национальной поверхности атаки** |
| `summary.end_of_life` | integer | **O** | Неподдерживаемое программное / аппаратное обеспечение |

### 4.4.3 `assets[]` — структура

Каждый актив состоит из двух частей: **общего ядра** (одинаково для всех классов) и **одного объекта, соответствующего классу**.

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

**Правило:** в каждом активе может быть **только объект, соответствующий его классу**. Например, если в активе `personnel` есть объект `technical`, payload отклоняется — у сотрудника не бывает IP-адреса или открытого порта.

### 4.4.4 Общее ядро — для всех классов

| Поле | Тип | R/O | Определение и допустимые значения |
|---|---|---|---|
| `asset_uid` | string | **R\*** | **Стабильный уникальный ID — основной связующий ключ.** Должен записываться точно так же, как `affected_asset_uids` в incident и `device.hostname` в alert. Не меняется между снимками. |
| `asset_class` | enum | **R\* · STD** | Один из 12 классов: `information` │ `process` │ `hardware` │ `software` │ `network` │ `service` │ `information_resource` │ `security_tool` │ `personnel` │ `site` │ `organization` │ `intangible` |
| `asset_type` | enum | **R\* · STD** | Один из 70 типов. **Должен соответствовать выбранному классу.** Полный перечень: **Приложение E** |
| `criticality` | enum | **O** | `crown_jewel` │ `high` │ `medium` │ `low` |
| `lifecycle_status` | enum | **O** | `active` │ `decommissioned` │ `end_of_life`. Единственный способ удалить актив — `decommissioned` (§4.2). |
| `provenance` | enum | **O** | `discovered` — обнаружен средством (факт) │ `declared` — введён вручную (утверждение) |
| `first_seen` | timestamp | **O** | Время первого наблюдения. Показывает рост неуправляемых активов (shadow IT). |
| `last_seen` | timestamp | **O** | Время последнего наблюдения. Правило устаревания применяется только к активам `discovered`. |
| `related_asset_uids` | array[string] | **O** | `asset_uid` связанных активов. См. примеры ниже. |

> **В классе `personnel` `asset_uid` должен быть анонимным.** Имя, логин, email, телефон не указываются: `role-ciso`, `role-soc-lead`, `user-0417`. Контакты для связи во время инцидента относятся не к телеметрии, а к регистрационным данным организации.

**`related_asset_uids` — связи между активами:**

| Актив | `related_asset_uids` | Значение |
|---|---|---|
| `information_resource/web_resource` | `["web014"]` | Веб-ресурс работает на этом сервере |
| `information/processed_data` | `["db02"]` | Данные хранятся в этой базе |
| `process/business_process` | `["app-payments", "db02"]` | Процесс зависит от этого приложения и базы |
| `personnel/responsible_person` | `["web014", "db02"]` | Ответственное лицо отвечает за эти активы |
| `organization/supplier` | `["fw01"]` | Поставщик обслуживает это устройство |

Национальная ценность реестровых активов заключается именно в этих связях: например, «от каких серверов зависит платёжный процесс» или «к каким системам имеет доступ этот поставщик».

### 4.4.5 `technical` — технические классы

`hardware`, `software`, `network`, `service`, `information_resource`, `security_tool` — для этих шести классов объект **обязателен**. В остальных классах запрещён.

| Поле | Тип | R/O | Определение и допустимые значения |
|---|---|---|---|
| `hostname` | string | **O** | Полный hostname / FQDN (`web014.bank.local`) |
| `manufacturer` | string | **O** | Производитель оборудования: `"Dell"`, `"HP"`, `"Cisco"`. Для реагирования на уязвимости цепочки поставок. |
| `model` | string | **O** | Модель: `"PowerEdge R750"` |
| `os.type_id` | integer | **O · STD** | Enum OCSF, такой же, как в alert: `0` Unknown · `100` Windows · `101` Windows Mobile · `200` Linux · `201` Android · `300` macOS · `301` iOS · `302` iPadOS · `400` Solaris · `401` AIX · `402` HP-UX · `99` Other (Приложение B.4) |
| `os.name` | string | **O** | `"Ubuntu Server"`, `"Windows Server"` |
| `os.version` | string | **O** | `"22.04"`, `"2022"` |
| `os.build` | string | **O** | Build / уровень патча: `"5.15.0-101"`, `"20348.2402"` |
| `ip_addresses[].value` | string | **R\*** | IP-адрес |
| `ip_addresses[].type` | enum | **O** | `ipv4` │ `ipv6` |
| `ip_addresses[].scope` | enum | **R\*** | `internal` │ `public` │ `dmz` |
| `mac_addresses` | array[string] | **O** | MAC-адреса, в нижнем регистре, через двоеточие: `["00:1a:2b:3c:4d:5e"]`. Для сопоставления с `device.mac` в alert — резервный способ связи, когда `hostname` не совпадает. |
| `open_ports` | array[integer] | **O** | Открытые порты: `[22, 80, 443]`, 0–65535 |
| `as_protection_class` | enum | **O · STD** | Класс защищённости автоматизированной системы от несанкционированного доступа (**O'z DSt 2814:2014**; O'zMSt 816:2025 §7.9.4): `3B` │ `3A` │ `2B` │ `2A` │ `1D` │ `1G` │ `1V` │ `1B` │ `1A`. **Только для типов `information_system` и `industrial_control_system`** — для других типов отклоняется |
| `exposure` | enum | **R\*** | `internet_facing` │ `dmz` │ `internal`. **Важнейший фильтр** — на нём основано представление «критические уязвимости на активах, открытых в интернет». |
| `environment` | enum | **O** | `production` │ `staging` │ `development` │ `test` |
| `software_inventory[].product` | string | **R\*** | Название продукта: `"Apache HTTP Server"` |
| `software_inventory[].version` | string | **O** | Установленная версия. Без версии сопоставление с CVE не работает. |
| `software_inventory[].cpe` | string | **O · STD** | CPE 2.3: `cpe:2.3:<part>:<vendor>:<product>:<version>:...` — 13 частей, пустые — `*`. Источник: `https://nvd.nist.gov/products/cpe` |
| `known_cves[].cve_id` | string | **R\* · STD** | `CVE-YYYY-NNNN+`, в верхнем регистре. **Связующий ключ национального раннего предупреждения.** |
| `known_cves[].status` | enum | **O** | `unpatched` │ `patched` │ `mitigated` │ `accepted_risk` |
| `known_cves[].detected_at` | timestamp | **O** | Время обнаружения уязвимости |

> **Разница между `exposure` и `ip_addresses[].scope`.** Актив может иметь внутренний IP (`scope: internal`) и при этом быть доступным из интернета через NAT или reverse proxy (`exposure: internet_facing`). Поэтому нужны оба поля.

> **Зачем нужен `software_inventory`, если есть `known_cves`.** Когда публикуется новая критическая CVE, сканеры организаций ещё не обновлены. UzCORE же по данным о новой CVE и перечню программного обеспечения сразу определяет, кто может пострадать. `cpe` делает это сопоставление точным.

### 4.4.6 Объекты реестровых классов

Отдельные объекты для классов `information`, `process`, `personnel`, `site`, `organization`, `intangible`. Поля определены на основе средств контроля **ISO/IEC 27002:2022** и принципов оценки рисков **ISO/IEC 27005:2022**.

Все поля **необязательные**. Пустой объект (`{}`) также считается корректным — организация сама решает, какие поля заполнять.

---

#### `information` — информационные активы

Основа: **приложение L O'zMSt 816:2025** (категории ограничения доступа, целостности и доступности); ISO 27002 **5.33** (защита записей), **5.34** (PII), **8.10** (удаление), **8.11** (маскирование), **8.12** (DLP), **8.13** (резервное копирование), **8.24** (криптография).

| Поле | Тип | R/O | Определение и допустимые значения |
|---|---|---|---|
| `confidentiality_marks` | array[enum] | **O · STD** | Категории ограничения доступа — таблица ниже. **Допускается несколько одновременно**: `["PD","BT"]`. `OD` только отдельно |
| `integrity_category` | enum | **O · STD** | `V` │ `N` │ `-` — таблица ниже |
| `availability_category` | enum | **O · STD** | `B` │ `V` │ `S` │ `N` — таблица ниже |
| `data_categories` | array[enum] | **O** | `financial` │ `health` │ `biometric` │ `commercial_secret` │ `operational` │ `technical` │ `telemetry` │ `other` |
| `contains_pii` | boolean | **O** | Содержатся ли персональные данные (27002 5.34) |
| `pii_volume_band` | enum | **O** | `none` │ `under_1k` │ `under_100k` │ `under_1m` │ `over_1m`. **Точное число не указывается.** При `contains_pii: false` — только `none` |
| `storage_location` | enum | **O** | `on_premise` │ `national_cloud` │ `foreign_cloud` │ `hybrid` │ `offline` — резидентность данных (27002 5.23) |
| `retention_days` | integer | **O** | Срок хранения, в днях. `0` — срок не установлен (27002 5.33, 8.10) |
| `encryption.at_rest` | boolean | **O** | Шифруются ли при хранении (27002 8.24) |
| `encryption.in_transit` | boolean | **O** | Шифруются ли при передаче |
| `masking_applied` | boolean | **O** | Применяется ли маскирование / псевдонимизация (27002 8.11) |
| `dlp_applied` | boolean | **O** | Охвачены ли средством DLP (27002 8.12) |
| `backup.exists` | boolean | **O** | Есть ли резервная копия (27002 8.13) |
| `backup.frequency` | enum | **O** | `continuous` │ `hourly` │ `daily` │ `weekly` │ `monthly` │ `none` |
| `backup.offsite` | boolean | **O** | Хранится ли резервная копия в другом физическом месте |
| `backup.last_tested_at` | date | **O** | `YYYY-MM-DD`. Дата последней проверки восстановления |
| `regulatory_scope` | array[enum] | **O** | `pq_167` │ `personal_data_law` │ `state_secret` │ `banking` │ `healthcare` │ `pci_dss` │ `gdpr` │ `other` (27002 5.31, 5.34) |

**Категории согласно приложению L O'zMSt 816:2025:**

| Поле | Код | Значение |
|---|---|---|
| `confidentiality_marks` | `SS` | Государственная тайна — совершенно секретно |
| | `S` | Государственная тайна — секретно |
| | `DSP` | Для служебного пользования |
| | `KT` | Коммерческая тайна |
| | `BT` | Банковская тайна |
| | `PD` | Персональные данные |
| | `KO` | Конфиденциальные данные организации |
| | `OD` | Открытые данные |
| `integrity_category` | `V` | Высокая — несанкционированное изменение наносит существенный прямой ущерб |
| | `N` | Низкая — незначительный, неопределённый ущерб |
| | `-` | Обеспечение целостности не требуется |
| `availability_category` | `B` | Бесперебойная — простой не превышает **1 минуты** |
| | `V` | Высокая — простой не превышает **1 часа** |
| | `S` | Средняя — простой не превышает **12 часов** |
| | `N` | Низкая — простой может превышать 12 часов |

**Соответствие типа и категорий** — проверяется схемой:

| `asset_type` | Должно присутствовать в `confidentiality_marks` |
|---|---|
| `state_secret` | `SS` или `S` |
| `confidential_data` | Хотя бы одно из `DSP`, `KT`, `BT`, `PD` или `KO` |
| `personal_data` | `PD` |
| `public_data` | Только `["OD"]` |

Метка `PD` и `contains_pii` не должны противоречить друг другу: при наличии `PD` значение `contains_pii: false` отклоняется, при `contains_pii: true` метка `PD` обязательна.

---

#### `process` — бизнес-процессы

Основа: ISO 27002 **5.29** (безопасность во время нарушения), **5.30** (непрерывность ИКТ, BIA), **5.2** (роли); ISO 27005 **7.3.2**.

| Поле | Тип | R/O | Определение и допустимые значения |
|---|---|---|---|
| `process_owner_uid` | string | **O** | `asset_uid` владельца процесса — **анонимный** ID из класса `personnel`. Имя не указывается (27002 5.2) |
| `citizen_facing` | boolean | **O** | Влияет ли нарушение непосредственно на граждан. **Поле, определяющее национальный приоритет** |
| `availability_category` | enum | **O · STD** | `B` │ `V` │ `S` │ `N` — приложение L O'zMSt 816:2025, та же шкала, что и в `information` |
| `bia.completed` | boolean | **O** | Проведён ли анализ воздействия на бизнес (27002 5.30) |
| `bia.last_review_at` | date | **O** | `YYYY-MM-DD` |
| `bia.rto_minutes` | integer | **O** | **RTO** — целевое время восстановления, в минутах |
| `bia.rpo_minutes` | integer | **O** | **RPO** — допустимое окно потери данных, в минутах |
| `bia.mtpd_minutes` | integer | **O** | **MTPD** — максимально допустимая продолжительность нарушения |
| `continuity_plan.exists` | boolean | **O** | Есть ли план непрерывности (27002 5.29, 5.30) |
| `continuity_plan.last_tested_at` | date | **O** | Дата последнего тестирования плана |
| `continuity_plan.manual_fallback` | boolean | **O** | Есть ли возможность ручного выполнения при неработающих ИТ |
| `impact_if_disrupted` | enum | **O** | `low` │ `medium` │ `high` │ `critical` |
| `regulatory_scope` | array[enum] | **O** | Тот же перечень, что и в `information` |

---

#### `personnel` — сотрудники и роли

Основа: ISO 27002 **5.2** (роли), **5.3** (разделение обязанностей), **6.1** (проверка), **6.2** (договор), **6.3** (обучение), **6.6** (NDA), **6.7** (удалённая работа), **8.2** (привилегированный доступ).

> ## ⚠️ ПЕРСОНАЛЬНЫЕ ДАННЫЕ ЗАПРЕЩЕНЫ
>
> В этом объекте **нет имени, фамилии, логина, email, телефона, даты рождения, названия должности в свободной форме**. Схема их не принимает — `additionalProperties: false`.
>
> **Рекомендация:** использовать `represents: "role"` или `"group"`. Представление роли вместо отдельного лица усиливает анонимность и делает перечень стабильным.

| Поле | Тип | R/O | Определение и допустимые значения |
|---|---|---|---|
| `represents` | enum | **O** | `individual` │ `role` │ `group` — кого представляет запись |
| `headcount` | integer | **O** | Количество людей в этой роли/группе. **Запрещено при `represents: "individual"`** |
| `role_category` | enum | **O** | `executive` │ `ciso` │ `security_officer` │ `soc_analyst` │ `system_admin` │ `network_admin` │ `dba` │ `developer` │ `ot_engineer` │ `help_desk` │ `auditor` │ `general_user` │ `other` (27002 5.2) |
| `employment_type` | enum | **O** | `employee` │ `contractor` │ `third_party` │ `intern` (27002 6.2, 5.19) |
| `privileged_access` | boolean | **O** | Есть ли право привилегированного доступа (27002 8.2) |
| `privileged_scope` | array[enum] | **O** | `domain_admin` │ `server_admin` │ `database` │ `network` │ `ot_ics` │ `cloud` │ `security_tools` │ `backup` │ `source_code`. **Только при `privileged_access: true`** |
| `segregation_of_duties_conflict` | boolean | **O** | Нарушено ли разделение обязанностей (27002 5.3) |
| `screening_completed` | boolean | **O** | Проведена ли проверка перед приёмом на работу (27002 6.1) |
| `nda_signed` | boolean | **O** | Подписано ли соглашение о конфиденциальности (27002 6.6) |
| `security_training.completed` | boolean | **O** | Пройден ли курс осведомлённости (27002 6.3) |
| `security_training.last_completed_at` | date | **O** | `YYYY-MM-DD` |
| `remote_access` | boolean | **O** | Есть ли право удалённой работы (27002 6.7) |
| `access_to_confidentiality_marks` | array[enum] | **O · STD** | Категории данных, к которым есть доступ — коды из `information.confidentiality_marks`: `["KO","PD"]` |

---

#### `site` — физические объекты

Основание: ISO 27002 **7.1** (периметр), **7.2** (контроль доступа), **7.3** (защита помещений), **7.4** (физическое наблюдение), **7.5** (природные угрозы), **7.11** (поддерживающая инфраструктура).

> **ТОЧНЫЙ АДРЕС НЕ УКАЗЫВАЕТСЯ.** Улицы, номера здания и GPS-координат в схеме нет. Только **код региона** — ISO 3166-2:UZ.

| Поле | Тип | R/O | Описание и допустимые значения |
|---|---|---|---|
| `site_type` | enum | **O** | `datacenter` │ `colocation` │ `server_room` │ `office` │ `branch` │ `industrial_plant` │ `substation` │ `dr_site` │ `warehouse` │ `remote_facility` |
| `region_code` | enum | **O · STD** | ISO 3166-2:UZ — `UZ-AN` Андижан · `UZ-BU` Бухара · `UZ-FA` Фергана · `UZ-JI` Джизак · `UZ-NG` Наманган · `UZ-NW` Навои · `UZ-QA` Кашкадарья · `UZ-QR` Каракалпакстан · `UZ-SA` Самарканд · `UZ-SI` Сырдарья · `UZ-SU` Сурхандарья · `UZ-TK` г. Ташкент · `UZ-TO` Ташкентская обл. · `UZ-XO` Хорезм · `FOREIGN` — за пределами страны |
| `ownership` | enum | **O** | `owned` │ `leased` │ `colocation` │ `third_party` (27002 5.19) |
| `secure_area` | boolean | **O** | Определён ли объект как защищённая зона (27002 7.1, 7.3, 7.6) |
| `physical_access_control` | array[enum] | **O** | `none` │ `key` │ `badge` │ `pin` │ `biometric` │ `mantrap` │ `guard` │ `visitor_log` (27002 7.2) |
| `physical_monitoring` | array[enum] | **O** | `none` │ `cctv` │ `intruder_alarm` │ `guard_patrol` │ `access_log` │ `environmental_sensor` (27002 7.4) |
| `supporting_utilities` | array[enum] | **O** | `ups` │ `generator` │ `redundant_power` │ `cooling` │ `fire_suppression` │ `water_detection` │ `redundant_telecom` (27002 7.11) |
| `environmental_threats` | array[enum] | **O** | `none` │ `seismic` │ `flood` │ `fire` │ `extreme_heat` │ `dust` │ `power_instability` (27002 7.5) |
| `hosts_critical_assets` | boolean | **O** | Размещены ли на этом объекте активы `crown_jewel` или `high` |

---

#### `organization` — внешние организации и подразделения

Основание: ISO 27002 **5.19** (отношения с поставщиками), **5.20** (условия безопасности в договоре), **5.21** (цепочка поставок ИКТ), **5.22** (мониторинг и пересмотр услуг), **5.23** (облачные услуги); ISO 27005 **7.2**.

| Поле | Тип | R/O | Описание и допустимые значения |
|---|---|---|---|
| `org_role` | enum | **O** | `supplier` │ `ict_supplier` │ `cloud_provider` │ `mssp` │ `subcontractor` │ `internal_unit` │ `partner` │ `regulator` |
| `org_ref` | string | **O** | Регистрационный код **юридического лица** (ИНН/STIR). Код физического лица или ИП **не указывается** |
| `country_code` | string | **O · STD** | ISO 3166-1 alpha-2, заглавными буквами: `UZ`, `RU`, `CN`, `US` (27002 5.21) |
| `access_type` | array[enum] | **O** | `none` │ `physical` │ `remote_logical` │ `privileged` │ `data_processing` │ `source_code` │ `onsite_staff` │ `managed_security` (27002 5.19, 5.20) |
| `agreement.nda` | boolean | **O** | Есть ли соглашение о конфиденциальности |
| `agreement.security_clauses` | boolean | **O** | Есть ли в договоре условия безопасности (27002 5.20) |
| `agreement.sla` | boolean | **O** | Есть ли SLA |
| `agreement.right_to_audit` | boolean | **O** | Есть ли право на проведение аудита |
| `agreement.incident_notification` | boolean | **O** | Есть ли обязательство уведомлять об инцидентах |
| `security_certification` | array[enum] | **O** | `none` │ `iso_27001` │ `iso_22301` │ `pci_dss` │ `soc2` │ `national_cert` │ `other` (27002 5.21, 5.22) |
| `last_review_at` | date | **O** | Дата последней проверки безопасности (27002 5.22) |
| `concentration_risk` | boolean | **O** | Есть ли безальтернативная зависимость от этого поставщика (27005 7.2) |

---

#### `intangible` — нематериальные активы

Основание: O'zMSt 816:2025 §7.9.2 f); O'zMSt ISO/IEC 27005:2024 A.2.2 — основной актив.

Поля ещё не определены — пока принимается только пустой объект (`{}`). У нематериального актива нет IP-адреса или уязвимости; его значимость — в связи с другими активами через `related_asset_uids`.

---

#### Пример — пять активов реестра

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

**Какие поля для какого класса:**

| Поле | hardware | software | network | service | information_resource | security_tool | information | process | personnel | site | organization | intangible |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Общее ядро | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `technical` | **R** | **R** | **R** | **R** | **R** | **R** | — | — | — | — | — | — |
| `information` | — | — | — | — | — | — | O | — | — | — | — | — |
| `process` | — | — | — | — | — | — | — | O | — | — | — | — |
| `personnel` | — | — | — | — | — | — | — | — | O | — | — | — |
| `site` | — | — | — | — | — | — | — | — | — | O | — | — |
| `organization` | — | — | — | — | — | — | — | — | — | — | O | — |
| `intangible` | — | — | — | — | — | — | — | — | — | — | — | O |

## 4.5 Минимальный пример asset

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

## 4.6 Частые ошибки

| Ошибка | Последствие | Правильное решение |
|---|---|---|
| Новый `asset_uid` в каждом снапшоте | Теряется историческая связь, каждый день появляются «новые активы» | Использовать стабильный ID |
| `asset_uid` = IP-адрес | При смене IP актив «исчезает» | Для технического актива — нормализованный hostname (правило §2.4.7). Если используется CMDB ID, `technical.hostname` заполняется обязательно |
| `affected_asset_uids` в инциденте в другом формате или внутренний ID SOAR | Инцидент не привязывается к активу | Hostname актива из SOAR, нормализованный по правилу §2.4.7 |
| MSSP объединил несколько клиентов в одном снапшоте | Данные отклоняются | Отдельный запрос для каждого `org_id` |
| `asset_type` не соответствует классу (`hardware` + `responsible_person`) | Ошибка `422` | Проверить по таблице Приложения E |
| Объект `technical` в активе `personnel` | Ошибка `422` — объект не соответствует классу | Только объект своего класса |
| В техническом активе нет `technical` или `exposure` | Ошибка `422` | `technical.exposure` обязательно |
| `name`, `email`, `login` в `personnel` | `422` — персональных данных в схеме нет | Только `role_category` и `represents` |
| `address` или координаты в `site` | `422` — поле не существует | `region_code` (ISO 3166-2:UZ) |
| `privileged_access: false` + `privileged_scope` | `422` — противоречивое состояние | Либо установить `true`, либо убрать `privileged_scope` |
| `represents: "individual"` + `headcount` | `422` — у одного человека нет численности | `represents: "group"` |
| `contains_pii: false` + `pii_volume_band: "under_1k"` | `422` — противоречие | `pii_volume_band: "none"` |
| `asset_type: "personal_data"` + `confidentiality_marks: ["KT"]` | `422` — тип и категория не соответствуют | Добавить метку `PD` |
| `confidentiality_marks: ["OD", "KO"]` | `422` — открытое и конфиденциальное вместе | Либо `["OD"]`, либо коды ограниченного доступа |
| `as_protection_class` на сервере | `422` — только для автоматизированных систем | Указывать в активе `information_resource/information_system` |
| `country_code: "uz"` | `422` — строчные буквы | `"UZ"` — ISO 3166-1 alpha-2, заглавные буквы |
| ИНН физического лица в `org_ref` | Персональные данные попадают в UzCORE | Только код юридического лица |
| `"5 yil"` вместо `retention_days` | `422` — тип integer | `1825` |
| `asset_uid` = имя или логин сотрудника в `personnel` | Персональные данные попадают в UzCORE | Анонимный ID: `role-ciso`, `user-0417` |
| Считать актив «удалённым», исключив его из списка | Актив остаётся в базе (upsert) | Отправить `lifecycle_status: "decommissioned"` |
| В `known_cves` записаны `cvss_score` или `kev_listed` | Ошибка `422` | Только `cve_id`, `status`, `detected_at` |
| `tlp` = `AMBER` | Запрос отклоняется | Для активов только `RED` |

---

# 5. Минимальный обязательный набор

Если у организации нет возможности реализовать полную схему, на **первом этапе** принимается следующий сокращённый набор. Остальное добавляется позже и не нарушает модель.

**Incident — минимальный:**
```
konvert: telemetry_type · schema_version · org_id · incidents[]
element: report_id · source_case_id · tlp
lifecycle.status_id · lifecycle.detected_at · lifecycle.opened_at · lifecycle.updated_at
classification.event_category · classification.title · classification.severity_id
technical.indicators[]
```

**Alert — минимальный:**
```
konvert: telemetry_type · schema_version · org_id · collected_at
element: class_uid · category_uid · activity_id · type_uid · time · severity_id
metadata.version · metadata.product.name
finding_info.uid · device.hostname
```

**Asset — минимальный:**
```
konvert: telemetry_type · schema_version · org_id · tlp · collected_at · summary.total_assets
aktiv:   asset_uid · asset_class · asset_type
texnik:  technical.exposure · technical.ip_addresses · technical.os · technical.software_inventory · technical.known_cves
```

> ## Три поля, которые никогда не опускаются
>
> | Поле | Что даёт |
> |---|---|
> | `technical.affected_asset_uids` | Связывает инциденты с реальными активами (когда активы известны) |
> | `technical.indicators[].value` | Выявляет межорганизационную кампанию |
> | `assets[].technical.known_cves` | Запускает национальное раннее оповещение по CVE |
>
> 

---

# 6. Чек-лист валидации

Перед запуском интеграции проверьте следующее:

**Общее**
- [ ] `GET /connector/me` вернул успешный ответ
- [ ] `key` не в коде, а в переменной окружения или secret manager
- [ ] Тело сериализуется один раз: хэшируемые и отправляемые байты полностью идентичны
- [ ] Все времена в UTC, для incident/asset — ISO 8601 с `Z`, внутри alert — epoch **ms**
- [ ] `org_id` в конверте — организация-**владелец** данных (не отправитель)
- [ ] Один `org_id` в одном запросе — клиенты MSSP не смешаны
- [ ] В теле нет `sender_id` — отправитель определяется через header `x-org-id`
- [ ] Нет сырых логов, паролей, командных строк, имён сотрудников
- [ ] Массив `errors` из ответа `422` логируется и читается

**Incident**
- [ ] `report_id` вычислен по формуле §1.5 (не случайный)
- [ ] `source_case_id` заполнен и не меняется на протяжении жизни инцидента
- [ ] Один инцидент = один `report_id`, в том числе при обновлениях
- [ ] `related_report_ids` ссылается только на другие инциденты (не содержит собственный `report_id`)
- [ ] `tlp` есть в каждом элементе инцидента (не в конверте)
- [ ] `status_id` замаплен из исходной системы по Приложению B.5, только в диапазоне `1`–`5`
- [ ] При `status_id` = `5` заполнен `closed_at`
- [ ] `event_type` соответствует выбранной `event_category` (Приложение A)
- [ ] `detected_at` ≤ `opened_at` ≤ `updated_at`
- [ ] `affected_asset_uids` заполнен, если активы известны, — не внутренний ID SOAR, а hostname, нормализованный по §2.4.7; иначе `[]`
- [ ] `indicators[].value` refang'нуты, в нижнем регистре, RFC 1918 отфильтрованы
- [ ] В `actions_taken` и `closing_note` нет имён хостов / IP / логинов
- [ ] `activity` — полная история, а не только новые записи
- [ ] В `activity` нет текста комментариев, только `time` и `type`
- [ ] В записях `status_changed` заполнен `to_status_id`

**Alert**
- [ ] Тело запроса — объект-конверт, массив `alerts[]` внутри него
- [ ] `org_id` и `collected_at` в конверте, а не внутри элементов alert
- [ ] `class_uid`=2004, `category_uid`=2, `activity_id`=1, `type_uid`=200401
- [ ] `metadata.version` = `"1.9.0"`
- [ ] `severity_id` только из `{0,1,2,3,4,5,99}`
- [ ] `finding_info.title` — название правила, а не текст события
- [ ] `device.hostname` нормализован и равен `asset_uid`
- [ ] `device.mac` в нижнем регистре (`00:1a:2b:3c:4d:5e`)

**Asset**
- [ ] `tlp` = `"RED"`
- [ ] `asset_uid` стабилен и не меняется между снапшотами
- [ ] `asset_type` соответствует выбранному `asset_class` (Приложение E)
- [ ] В каждом активе только объект, соответствующий его классу; в технических классах есть `technical.exposure`
- [ ] В объектах реестра только поля из §4.4.6; связанные поля не противоречат друг другу (`privileged_access`/`privileged_scope`, `represents`/`headcount`, `contains_pii`/`pii_volume_band`, `confidentiality_marks`/`asset_type`, `PD`/`contains_pii`)
- [ ] В `site` нет точного адреса — только `region_code`; `organization.org_ref` — только ИНН (STIR) юридического лица
- [ ] В активах `personnel` `asset_uid` анонимен — нет имени, логина, email
- [ ] `technical.os.type_id`: Linux = **200**, Windows = **100** (Приложение B.4)
- [ ] `technical.mac_addresses[]` в нижнем регистре — в том же формате, что и `device.mac` в alert
- [ ] `technical.known_cves[].cve_id` в верхнем регистре, в формате `CVE-YYYY-NNNN+`; CVSS/KEV не отправляются
- [ ] Выведенные из эксплуатации активы отправлены с `lifecycle_status: "decommissioned"`

**Тест связности (самое важное)**
- [ ] Выбран один тестовый актив
- [ ] Его `asset_uid` присутствует в снапшоте asset
- [ ] То же значение присутствует в `affected_asset_uids` инцидента
- [ ] То же значение присутствует в `device.hostname` alert
- [ ] Все три **посимвольно** идентичны

---

# Приложение A — Классификация инцидентов ENISA RSIT (полный каталог)

`classification.event_category` и `classification.event_type` берутся только из таблицы ниже. **`event_type` обязан принадлежать выбранной категории** — тип из другой категории не принимается.

В третьем столбце показано официальное написание ENISA (через дефис). UzCORE принимает форму с подчёркиванием (`_`) и внутри преобразует её в форму ENISA — это обеспечивает обмен с другими национальными CSIRT.

### 1. `abusive_content` — злоупотребляющий контент

| `event_type` | Написание ENISA | Описание |
|---|---|---|
| `spam` | `spam` | Незапрошенные массовые сообщения |
| `harmful_speech` | `harmful-speech` | Оскорбления, угрозы, клевета |
| `violence` | `violence` | Насилие, незаконный контент в отношении детей |

### 2. `malicious_code` — вредоносное ПО

| `event_type` | Написание ENISA | Описание |
|---|---|---|
| `infected_system` | `infected-system` | Заражённая система. **Ransomware также относится сюда.** |
| `c2_server` | `c2-server` | Сервер управления (C&C) |
| `malware_distribution` | `malware-distribution` | Ресурс, распространяющий вредоносное ПО |
| `malware_configuration` | `malware-configuration` | Конфигурация вредоносного ПО |

### 3. `information_gathering` — сбор информации

| `event_type` | Написание ENISA | Описание |
|---|---|---|
| `scanner` | `scanner` | Сканирование портов/уязвимостей |
| `sniffing` | `sniffing` | Прослушивание сетевого трафика |
| `social_engineering` | `social-engineering` | Социальная инженерия (кроме фишинга) |

### 4. `intrusion_attempts` — попытки вторжения

| `event_type` | Написание ENISA | Описание |
|---|---|---|
| `exploit` | `exploit` | Попытка эксплуатации известной уязвимости |
| `brute_force` | `brute-force` | Перебор учётных данных |
| `ids_alert` | `ids-alert` | Новая/неизвестная сигнатура атаки |

### 5. `intrusions` — успешное вторжение

| `event_type` | Написание ENISA | Описание |
|---|---|---|
| `privileged_account_compromise` | `privileged-account-compromise` | Скомпрометирована привилегированная учётная запись |
| `unprivileged_account_compromise` | `unprivileged-account-compromise` | Скомпрометирована обычная учётная запись |
| `application_compromise` | `application-compromise` | Скомпрометировано приложение |
| `system_compromise` | `system-compromise` | Система полностью скомпрометирована |
| `burglary` | `burglary` | Физическое проникновение |

### 6. `availability` — доступность

| `event_type` | Написание ENISA | Описание |
|---|---|---|
| `dos` | `dos` | Отказ в обслуживании |
| `ddos` | `ddos` | Распределённый DoS |
| `misconfiguration` | `misconfiguration` | Сбой из-за неправильной настройки |
| `sabotage` | `sabotage` | Умышленное причинение ущерба |
| `outage` | `outage` | Сбой, не связанный с атакой |

### 7. `information_content_security` — безопасность информации

| `event_type` | Написание ENISA | Описание |
|---|---|---|
| `unauthorised_information_access` | `unauthorised-information-access` | Несанкционированный доступ |
| `unauthorised_information_modification` | `unauthorised-information-modification` | Несанкционированное изменение |
| `data_leak` | `data-leak` | Утечка конфиденциальной информации |
| `data_loss` | `data-loss` | Потеря данных |

### 8. `fraud` — мошенничество

| `event_type` | Написание ENISA | Описание |
|---|---|---|
| `unauthorised_use_of_resources` | `unauthorized-use-of-resources` | Несанкционированное использование ресурсов (например, криптомайнинг) |
| `copyright` | `copyright` | Нарушение авторских прав |
| `masquerade` | `masquerade` | Действия от имени другого лица |
| `phishing` | `phishing` | Фишинг |

### 9. `vulnerable` — уязвимость (не инцидент, а состояние)

| `event_type` | Написание ENISA | Описание |
|---|---|---|
| `weak_crypto` | `weak-crypto` | Слабая криптография |
| `ddos_amplifier` | `ddos-amplifier` | Сервис, способный выступать усилителем DDoS |
| `potentially_unwanted_accessible` | `potentially-unwanted-accessible` | Открытый ненужный сервис |
| `information_disclosure` | `information-disclosure` | Раскрытие информации |
| `vulnerable_system` | `vulnerable-system` | Система с уязвимостью |

### 10. `other` — прочее

| `event_type` | Написание ENISA | Описание |
|---|---|---|
| `other` | `other` | Не подходит ни под одно из вышеперечисленного |
| `undetermined` | `undetermined` | Тип ещё не определён |

### A.1 Практические примеры — как классифицировать

| Ситуация | `event_category` | `event_type` | Дополнительно |
|---|---|---|---|
| LockBit ransomware зашифровал сервер | `malicious_code` | `infected_system` | `mitre_attacks`: TA0040 → T1486 |
| Попытки перебора пароля SSH | `intrusion_attempts` | `brute_force` | `mitre_attacks`: TA0006 → T1110 → T1110.001 |
| Перебор SSH **удался** | `intrusions` | `unprivileged_account_compromise` | Не попытка, а вторжение |
| Сотруднику пришло фишинговое письмо, не перешёл | `fraud` | `phishing` | — |
| Через фишинг украдены учётные данные | `intrusions` | `unprivileged_account_compromise` | `mitre_attacks`: TA0001 → T1566 |
| Сайт под DDoS | `availability` | `ddos` | — |
| База клиентов оказалась в интернете | `information_content_security` | `data_leak` | `severity_id: 5` |
| Web-сервер взломан через CVE | `intrusions` | `application_compromise` | `mitre_attacks`: TA0001 → T1190; CVE связывается через `alerts[]` |
| На сервере обнаружен криптомайнер | `fraud` | `unauthorised_use_of_resources` | — |
| Контроллер домена полностью захвачен | `intrusions` | `privileged_account_compromise` | `criticality: crown_jewel` |
| Внешний адрес сканирует порты | `information_gathering` | `scanner` | — |
| Ошибочное правило firewall, сервис недоступен | `availability` | `misconfiguration` | — |

# Приложение B — Каталог enum OCSF 1.9.0

Эти списки взяты с `https://schema.ocsf.io/1.9.0/`. Официальный источник всегда имеет приоритет — при сомнениях сверяйтесь с этим сайтом.

**Общее правило:** `0` = Unknown (неизвестно), `99` = Other (не попадает в каталог). Промежуточные числа не выдумываются.

### B.1 `severity_id` (одинаково для alert и incident)

| ID | Название |
|---|---|
| `0` | Unknown — источник не передал уровень критичности |
| `1` | Informational |
| `2` | Low |
| `3` | Medium |
| `4` | High |
| `5` | Critical |
| `99` | Other |

### B.2 Alert: `status_id`

| ID | Название |
|---|---|
| `0` | Unknown |
| `1` | New |
| `2` | In Progress |
| `3` | Suppressed — рассмотрен, признан false positive |
| `4` | Resolved |
| `5` | Archived |
| `99` | Other |

**Маппинг из исходных систем:**

| Значение источника | `status_id` |
|---|---|
| Sentinel `New` · Defender `new` · Elastic `open` · Splunk `new` · QRadar `OPEN` | `1` New |
| Sentinel `Active` · Defender `inProgress` · Elastic `acknowledged` · Splunk `in progress` | `2` In Progress |
| QRadar `HIDDEN` · алерты, закрытые как false positive | `3` Suppressed |
| Defender `resolved` · Splunk `resolved` | `4` Resolved |
| Sentinel `Closed` · Elastic `closed` · Splunk `closed` · QRadar `CLOSED` | `5` Archived |
| Wazuh — понятие статуса отсутствует | поле не отправляется |

> **ВНИМАНИЕ:** enum `status_id` для alert и incident **не совпадают**. `3` в alert — **Suppressed**, в incident — **On Hold**; `5` в alert — **Archived**, в incident — **Closed**. Так устроен сам OCSF — Detection Finding и Incident Finding являются отдельными классами. Для incident используйте таблицу из **Приложения B.5**.

### B.3 `observables[].type_id`

| ID | Название |
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

### B.4 `os.type_id` — enum с наибольшим числом ошибок

| ID | Название | Что входит |
|---|---|---|
| `0` | Unknown | — |
| `100` | Windows | Windows 10/11, Windows Server 2016/2019/2022 |
| `101` | Windows Mobile | — |
| `200` | Linux | Ubuntu, RHEL, CentOS, Debian, SUSE, Alpine, Rocky, Alma |
| `201` | Android | Только Android. Не Linux! |
| `300` | macOS | — |
| `301` | iOS | — |
| `302` | iPadOS | — |
| `400` | Solaris | — |
| `401` | AIX | — |
| `402` | HP-UX | — |
| `99` | Other | FreeBSD, Cisco IOS, проприетарные ОС |

> **Существуют только эти значения.** `1`, `102`, `202`, `203`, `403` — в OCSF отсутствуют, будут отклонены.

### B.5 Incident: `status_id` — маппинг из исходных систем

SOAR/SIEM-система каждой организации использует собственные названия статусов. Перед отправкой в UzCORE они **в обязательном порядке** переводятся в число `status_id` — исходный текст напрямую не отправляется.

**Допустимые значения — только пять:**

| ID | Название | Значение |
|---|---|---|
| `1` | New | Кейс открыт, над ним ещё никто не работал |
| `2` | In Progress | Аналитик ведёт работу |
| `3` | On Hold | Работа временно приостановлена — ожидается ответ внешней стороны |
| `4` | Resolved | Техническая работа завершена, кейс формально не закрыт |
| `5` | Closed | Кейс закрыт, `closed_at` заполнен |

`0` (Unknown) и `99` (Other) **намеренно отсутствуют**: кейс всегда находится в одном из этих пяти состояний.

**Расширенный маппинг — возможные варианты написания:**

| Статус источника (разные написания) | `status_id` |
|---|---|
| New · Draft · Open · Opened · Created · Pending · To Do · Unassigned · Yangi | `1` |
| In Progress · In Process · InProgress · In-Progress · Active · Investigating · Analysis · Triage · Assigned · Working · Contain · Eradicate · Recover · Jarayonda | `2` |
| On Hold · OnHold · On-Hold · Hold · Awaiting · Awaiting Caller · Awaiting Vendor · Awaiting Info · Waiting · Suspended · Paused · Deferred · Kutilmoqda | `3` |
| Resolved · Done · Remediated · Mitigated · Review · Pending Closure · Hal qilindi | `4` |
| Closed · Completed · Archive · Archived · Cancelled · Canceled · Duplicated · Rejected · Yopildi | `5` |

**По распространённым системам:**

| Исходная система | Статус источника | `status_id` |
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

**Правила маппинга:**

- **Этапы NIST не отражаются в `status_id`.** Статусы Contain / Eradicate / Recover в ServiceNow SecOps — все соответствуют `status_id: 2` (In Progress). Технический этап выражается в `response.containment_status`.
- **Разница между `4` Resolved и `5` Closed:** Resolved — техническая работа завершена, но кейс формально не закрыт (обычно ожидается подтверждение). Closed — кейс закрыт и `closed_at` заполнен.
- **Если подходящее значение не найдено**, выберите из таблицы **наиболее близкое**. Отправить `0` или `99` невозможно — они отклоняются схемой.
- Для системы, отсутствующей в списке, составьте таблицу маппинга самостоятельно и предоставьте её UzCORE при онбординге.

### B.6 Incident: `verdict_id` — заключение расследования

`verdict_id` — заключение, вынесенное аналитиком **после расследования** инцидента. Отличие от `status_id`: `status_id` показывает, **на каком этапе** находится работа, а `verdict_id` — **каков** результат.

**Что это даёт UzCORE:** доля false positive по секторам (если значительная часть инцидентов имеет `1`, правила обнаружения этого сектора не настроены); исключение ошибочных сигналов из национальной статистики; исключение двойного подсчёта дубликатов.

| ID | Название | Когда используется |
|---|---|---|
| `0` | Unknown | Расследование продолжается, вердикт ещё не вынесен. Обычное значение для открытых инцидентов. |
| `1` | False Positive | Инцидента не было — средство выдало ложный сигнал. Указывает на необходимость настройки правила. |
| `2` | True Positive | Подтверждён реальный инцидент безопасности. |
| `3` | Disregard | Реальный, но во внимание не принимается — незначительный, ошибочный или случайный. |
| `4` | Suspicious | Подозрительная активность, но вредоносность не подтверждена. |
| `5` | Benign | Реальная активность, но безвредная — например, действия самого администратора, запланированный тест. |
| `6` | Test | Инцидент в рамках учений, испытаний или пентеста. Исключается из национальной статистики. |
| `7` | Insufficient Data | Данных для заключения недостаточно — логи удалены, доступа к активу нет. |
| `8` | Security Risk | Не атака, но выявлена проблема безопасности — некорректная настройка, уязвимость. |
| `9` | Managed Externally | Инцидент урегулирован другой стороной — провайдером, вендором, другим SOC. |
| `10` | Duplicate | Повтор другого инцидента. Используется вместе с `related_report_ids` — он указывает, дубликатом какого инцидента является. |

`99` (Other) **намеренно отсутствует**: одиннадцать значений выше покрывают все практические случаи.

**Маппинг из исходных систем:**

| Значение источника | `verdict_id` |
|---|---|
| TheHive `TruePositive` · XSOAR `Resolved - True Positive` · Sentinel `TruePositive` | `2` |
| TheHive `FalsePositive` · Sentinel `FalsePositive` · XSOAR `False Positive` | `1` |
| TheHive `Duplicated` · XSOAR `Duplicate` | `10` |
| Sentinel `BenignPositive` · Kaspersky `Low priority` | `5` |
| TheHive `Indeterminate` · Sentinel `Undetermined` | `0` или `7` (при нехватке данных `7`) |
| Инцидент в рамках теста или учений · XSOAR `Test` | `6` |
| Урегулирован другой стороной | `9` |

**Когда заполняется:** пока инцидент открыт — `0` (или поле вовсе не записывается), после закрытия — фактическое заключение. Пара `status_id: 5` с `verdict_id: 0` — признак незавершённой работы.

### B.7 Incident: `containment_status` — этап реагирования

Показывает, на каком этапе цикла реагирования NIST SP 800-61 находится инцидент. **Не дублирует** `status_id` (рабочий процесс).

| Значение | Значение |
|---|---|
| `not_contained` | Локализация не выполнена, атака продолжается |
| `partially_contained` | Частично локализован |
| `contained` | Локализован, распространение остановлено |
| `eradicated` | Вредоносный компонент удалён из системы |
| `recovered` | Система возвращена в нормальную работу |

### B.8 Incident: `activity[].type` — события хронологии

| Значение | Когда записывается | Дополнительное поле |
|---|---|---|
| `case_opened` | Кейс открыт | — |
| `case_closed` | Кейс закрыт | — |
| `case_reopened` | Закрытый кейс открыт повторно | — |
| `status_changed` | Статус изменён | `to_status_id` (обязательное) |
| `comment_added` | Добавлен комментарий (**текст не отправляется**) | — |
| `task_created` | Поставлена задача | — |
| `task_completed` | Задача выполнена | — |
| `severity_changed` | Критичность переоценена | `to_severity_id` (обязательное) |
| `artifact_added` | Добавлен новый IOC или доказательство | — |
| `other` | Не соответствует перечисленному выше | — |

### B.9 Каталог тактик ATT&CK

Этап атаки выражается в incident через `technical.mitre_attacks[].tactic`, в alert — через `finding_info.attacks[].tactic.uid`. Если исходная система передаёт только название тактики, найдите ID в этой таблице.

| `tactic.uid` | Название |
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

# Приложение C — Извлечение полей из исходных систем

Практическая помощь: где в распространённых инструментах находятся нужные данные.

### C.1 Откуда берутся IOC (`indicators[]`)

| Система | Источник | Фильтр |
|---|---|---|
| **TheHive** | **Observables** кейса (`dataType`, `data`, `tlp`) | Только те, у которых `ioc: true` |
| **Cortex XSOAR** | **Indicators** инцидента (результат extraction rules) | По reputation/verdict |
| **Microsoft Sentinel** | **Entities** инцидента | Entity ≠ IOC. Исключить хост и пользователя жертвы |
| **Splunk SOAR** | **Artifacts** контейнера, поля CEF (`sourceAddress`, `fileHash`, `requestURL`) | Требуется таблица маппинга ключ CEF → `type` |
| **IBM QRadar SOAR** | **Artifacts** (IP Address, DNS Name, SHA-256, URL) | Типизированы, соответствуют напрямую |
| **Wazuh** | **Объекта кейса нет.** Берётся из полей алерта: `data.srcip`, `data.dstip`, `data.url`, `syscheck.sha256_after` | Отдельный маппинг для каждого декодера |

### C.2 Основной маппинг из Wazuh в OCSF

| Поле Wazuh | Поле OCSF | Примечание |
|---|---|---|
| `id` | `finding_info.uid` | Ключ идемпотентности |
| `rule.id` | `metadata.event_code` | — |
| `rule.description` | `finding_info.title`, `metadata.event_name` | — |
| `rule.level` (0–15) | `severity_id` | По таблице маппинга ниже (§3.4.3) |
| `rule.mitre.id` | `finding_info.attacks[].technique.uid` | В incident — `technical.mitre_attacks[].techniques[].uid` |
| `rule.mitre.tactic` (название) | `finding_info.attacks[].tactic.uid` | Требуется перевод из названия в ID — Приложение B.9 |
| `rule.firedtimes` | `count` | — |
| `timestamp` | `time` (epoch ms) | Преобразование из ISO 8601 в epoch ms обязательно |
| `agent.name` | `device.hostname` | **В нормализованном виде** — равно `assets[].asset_uid` |
| `agent.ip` | `device.ip` | — |
| `data.srcip` | `observables[]` `type_id: 2` | RFC 1918 фильтруется |
| `syscheck.sha256_after` | `observables[]` `type_id: 8` | — |
| `data.vulnerability.cve` | `vulnerabilities[].cve.uid` | — |
| `full_log` | — | **Не отправляется** — по соображениям конфиденциальности |

**Рекомендуемый маппинг Wazuh `rule.level` → `severity_id`:**

| `rule.level` | `severity_id` | Название |
|---|---|---|
| 0–3 | `1` | Informational |
| 4–6 | `2` | Low |
| 7–9 | `3` | Medium |
| 10–12 | `4` | High |
| 13–15 | `5` | Critical |

---

# Приложение D — Официальные файлы JSON Schema

Вместе с документом предоставляются три файла JSON Schema. Они написаны по стандарту **JSON Schema draft 2020-12** и выражают все правила документа в машиночитаемой форме.

| Файл | Назначение |
|---|---|
| `incident-report.schema.json` | Пакет incident (конверт + `incidents[]`) |
| `alert.schema.json` | Пакет alert (конверт + `alerts[]`) |
| `asset-inventory.schema.json` | Пакет asset (конверт + `assets[]`): общее ядро + объект, соответствующий классу |

**Что они проверяют:**
- Соответствие RSIT `event_category` ↔ `event_type` (через `if`/`then`, отдельно для каждой категории)
- Условную обязательность: `closed_at` (при `status_id` 5); `start_time`, если в alert есть `end_time`; для asset — соответствие `asset_type` ↔ `asset_class` и в каждом классе только свой объект (`technical` или объект реестра)
- `additionalProperties: false` — поля, отсутствующие в схеме, отклоняются
- Правила форматов: UUID, ISO 8601 с `Z`, `CVE-YYYY-NNNN+`, CPE 2.3, MITRE `T####[.###]`
- Enum OCSF: `severity_id`, `status_id`, `os.type_id`, `observables[].type_id` и другие

**Правила, которые схема проверить не может и которые проверяет сервер:** `start_time ≤ end_time`, `detected_at ≤ opened_at ≤ updated_at`, соответствие значений `summary` содержимому `assets[]`.

**Использование — Python:**

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

# Приложение E — Таксономия активов (классы и типы)

Таксономия составлена на основе **O'zMSt 816:2025** §7.9.2 (объекты защиты) и расширена с учётом **O'zMSt ISO/IEC 27005:2024**, **ISO/IEC 27001:2022 Annex A**, а также постановления Президента Республики Узбекистан **ПҚ-167** ([lex.uz/docs/6479190](https://lex.uz/docs/6479190)). Значения `asset_class` и `asset_type` записываются в точности как указано ниже.

**Как выбирать:** сначала определите класс актива, затем выберите наиболее подходящий тип внутри этого класса. Один актив относится только к одному классу. Связи между активами указываются через `related_asset_uids` (O'zMSt ISO/IEC 27005:2024 A.2.2 — граф зависимостей активов).

Столбец `iso27005_category` обозначает вид актива: **primary** — основной (информация и процессы), **supporting** — поддерживающий (ресурсы, которые их обеспечивают).

**Два осознанных отклонения от 816:** `source_code` — в 816 входит в состав программного обеспечения (§7.9.2 c)3)), здесь — в классе `information`, поскольку исходный код защищается как информация и не имеет сетевых характеристик. `passive_network_equipment` — в 816 входит в состав сети (§7.9.2 c)4)), здесь — в классе `site`, поскольку шкафы и кабельные каналы являются физической инфраструктурой.

| Класс | Число типов | Объект |
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

Итого: **12 классов, 70 типов.**

### E.1 `information`

| `asset_type` | ISO 27005 | Описание | Основание |
|---|---|---|---|
| `processed_data` | primary | Данные в цифровой, материальной или нематериальной форме | 816: §7.9.2 a); 27005: A.2.2; 27001: A.5.9; ПҚ-167: §11, §13 |
| `state_secret` | primary | Государственные секреты (SS – совершенно секретно; S – секретно) | 816: §7.9.2 a); приложение L; 27005: A.2.2; 27001: A.5.12 |
| `confidential_data` | primary | Конфиденциальные данные (DSP – для служебного пользования; KT – коммерческая тайна; BT – банковская тайна; KO – конфиденциальные данные организации) | 816: §7.9.2 a); приложение L; 27005: A.2.2; 27001: A.5.12 |
| `personal_data` | primary | Персональные данные (PD) | 816: §7.9.2 a); приложение L; 27005: A.2.2; 27001: A.5.34 |
| `public_data` | primary | Открытые данные (OD) | 816: приложение L; 27005: A.2.2; 27001: A.5.12 |
| `transmitted_data` | primary | Данные, передаваемые по каналам связи | 816: §7.9.2 c)4); 27005: A.2.2; 27001: A.8.20; ПҚ-167: §12 |
| `source_code` | supporting | Исходные коды | 816: §7.9.2 c)3); 27005: A.2.2; 27001: A.8.4 |
| `configuration` | supporting | Конфигурационные файлы систем и устройств, архитектура | 816: таблица L.1 (9); 27005: A.2.2; 27001: A.8.9; ПҚ-167: §11–§13 |
| `backup` | supporting | Резервные копии | 816: таблица L.1 (1); 27005: A.2.2; 27001: A.8.13 |
| `credential` | supporting | Аутентификационные данные | 27005: A.2.2; 27001: A.5.17 |
| `cryptographic_key` | supporting | Криптографические ключи | 27005: A.2.2; 27001: A.8.24 |
| `log_data` | supporting | Журналы аудита и событий | 27005: A.2.2; 27001: A.8.15 |

### E.2 `process`

| `asset_type` | ISO 27005 | Описание | Основание |
|---|---|---|---|
| `business_process` | primary | Бизнес-процессы организации | 816: §7.9.5 c); 27005: A.2.2; 27001: A.5.30 |

### E.3 `hardware`

| `asset_type` | ISO 27005 | Описание | Основание |
|---|---|---|---|
| `endpoint` | supporting | Оконечные устройства пользователей | 816: §7.9.2 c)1); 27005: A.2.2 (аппаратное обеспечение); 27001: A.8.1; ПҚ-167: §11 |
| `server` | supporting | Серверы | 816: §7.9.2 c)1); 27005: A.2.2 (аппаратное обеспечение); 27001: A.8.1; ПҚ-167: §11 |
| `industrial_server` | supporting | Промышленные серверы (АСУ) | 27005: A.2.2 (аппаратное обеспечение); ПҚ-167: §13 |
| `storage_system` | supporting | Системы хранения данных | 816: §7.9.2 c)1); 27005: A.2.2 (аппаратное обеспечение); 27001: A.7.10; ПҚ-167: §11 |
| `removable_media` | supporting | Съёмные носители информации | 816: §7.9.2 c)1); 27005: A.2.2 (аппаратное обеспечение); 27001: A.7.10; ПҚ-167: §6 |
| `mobile` | supporting | Мобильные устройства | 816: §7.9.2 c)2); 27005: A.2.2 (аппаратное обеспечение); 27001: A.8.1; ПҚ-167: §11 |
| `atm` | supporting | Банкоматы | 816: §7.9.2 c)2); 27005: A.2.2 (аппаратное обеспечение) |
| `infokiosk` | supporting | Инфокиоски | 816: §7.9.2 c)2); 27005: A.2.2 (аппаратное обеспечение) |
| `payment_terminal` | supporting | Платёжные терминалы | 816: §7.9.2 c)2); 27005: A.2.2 (аппаратное обеспечение) |
| `plc` | supporting | Программируемые логические контроллеры | 27005: A.2.2 (аппаратное обеспечение); ПҚ-167: §13 |
| `technological_equipment` | supporting | Производственное и технологическое оборудование | 27005: A.2.2 (аппаратное обеспечение); ПҚ-167: §13 |
| `iot_device` | supporting | Прочие отдельные устройства (IoT) | 816: §7.9.2 c)2); 27005: A.2.2 (аппаратное обеспечение); 27001: A.8.1 |
| `virtual_machine` | supporting | Виртуальные машины | 27005: A.2.2 (аппаратное обеспечение); 27001: A.8.9; ПҚ-167: §14 |
| `container` | supporting | Контейнеры | 27005: A.2.2 (аппаратное обеспечение); 27001: A.8.9; ПҚ-167: §14 |
| `media_processing_device` | supporting | Средства обработки графической, видео- и речевой информации | 27005: A.2.2 (аппаратное обеспечение); ПҚ-167: §11 |

### E.4 `software`

| `asset_type` | ISO 27005 | Описание | Основание |
|---|---|---|---|
| `operating_system` | supporting | Операционные системы | 816: §7.9.2 c)3); 27005: A.2.2 (приложение); 27001: A.8.19; ПҚ-167: §11–§13 |
| `application` | supporting | Прикладное программное обеспечение и приложения | 816: §7.9.2 c)3); 27005: A.2.2 (приложение); 27001: A.8.26; ПҚ-167: §11–§13 |
| `dbms` | supporting | Системы управления базами данных | 816: §7.9.2 c)3); 27005: A.2.2 (приложение); 27001: A.8.26; ПҚ-167: §11 |
| `diagnostic_tool` | supporting | Диагностические программы | 816: §7.9.2 c)3); 27005: A.2.2 (приложение); 27001: A.8.18 |
| `dev_tool` | supporting | Инструментальные средства разработки | 816: §7.9.2 c)3); 27005: A.2.2 (приложение); 27001: A.8.4 |
| `utility` | supporting | Вспомогательные программы | 816: §7.9.2 c)3); 27005: A.2.2 (приложение); 27001: A.8.18 |
| `firmware` | supporting | Программное обеспечение программно-аппаратных средств | 27005: A.2.2 (приложение); 27001: A.8.9; ПҚ-167: §11, §13 |

### E.5 `network`

| `asset_type` | ISO 27005 | Описание | Основание |
|---|---|---|---|
| `corporate_network` | supporting | Корпоративные и/или локальные сети | 816: §7.9.2 c)4); 27005: A.2.2 (сеть); 27001: A.8.20; ПҚ-167: §12 |
| `comm_channel` | supporting | Каналы связи (корпоративные, удалённое подключение, подключение к внешним сетям) | 816: §7.9.2 c)4); 27005: A.2.2 (сеть); 27001: A.8.20; ПҚ-167: §11–§13 |
| `active_network_device` | supporting | Активное сетевое оборудование – коммутаторы, маршрутизаторы, модемы | 816: §7.9.2 c)4); 27005: A.2.2 (сеть); 27001: A.8.20; ПҚ-167: §12 |
| `network_segment` | supporting | Сетевой сегмент – VLAN, DMZ | 816: §7.17 (VLAN); 27005: A.2.2 (сеть); 27001: A.8.22; ПҚ-167: §12 |
| `telecom_management_system` | supporting | Система управления телекоммуникационной сетью | 27005: A.2.2 (сеть); 27001: A.8.20; ПҚ-167: §12 |

### E.6 `service`

| `asset_type` | ISO 27005 | Описание | Основание |
|---|---|---|---|
| `email_system` | supporting | Электронная почта | 816: §7.9.2 c)5); §8.6.2; 27005: A.2.2 (сервис); 27001: A.5.14; ПҚ-167: §11 |
| `video_conferencing` | supporting | Видеоконференцсвязь | 816: §7.9.2 c)5); 27005: A.2.2 (сервис); 27001: A.5.14 |
| `ip_telephony` | supporting | IP-телефония | 816: §7.9.2 c)5); 27005: A.2.2 (сервис); 27001: A.5.14 |
| `messaging` | supporting | Системы мгновенного обмена сообщениями (мессенджеры) | 816: §7.9.2 c)5); 27005: A.2.2 (сервис); 27001: A.5.14 |
| `edms` | supporting | Система электронного документооборота | 816: §7.9.2 c)5); §8.6.2; 27005: A.2.2 (сервис); 27001: A.5.14 |
| `identity_service` | supporting | Сервис идентификации и аутентификации (контроллер домена, IdP) | 816: таблица L.1 (9); 27005: A.2.2 (сервис); 27001: A.5.16; ПҚ-167: §11 |
| `dns_service` | supporting | Сервис DNS | 27005: A.2.2 (сервис); 27001: A.8.21 |
| `cloud_service` | supporting | Облачные сервисы | 27005: A.2.2 (сервис); 27001: A.5.23 |
| `managed_service` | supporting | Сервис внешнего поставщика | 27005: A.2.2 (сервис); 27001: A.5.19 |

### E.7 `information_resource`

| `asset_type` | ISO 27005 | Описание | Основание |
|---|---|---|---|
| `file_storage` | supporting | Системы хранения файлов (файл-сервер) | 816: §7.9.2 c)6); §8.6.2; 27005: A.2.2; 27001: A.8.3; ПҚ-167: §11 |
| `web_resource` | supporting | Внутренние или внешние веб-ресурсы | 816: §7.9.2 c)6); §8.6.2; 27005: A.2.2; 27001: A.8.26; ПҚ-167: §11 |
| `database` | supporting | Локальная или входящая в информационную систему база данных | 816: §7.9.2 c)6); §8.6.2; 27005: A.2.2; 27001: A.8.26; ПҚ-167: §11 |
| `information_system` | supporting | Информационная (автоматизированная) система | 816: §7.9.2 c); §7.9.4; 27005: A.2.2; 27001: A.8.9; ПҚ-167: §11 |
| `industrial_control_system` | supporting | Автоматизированная система управления (АСУ) | 816: §7.9.3; 27005: A.2.2; ПҚ-167: §13 |

### E.8 `security_tool`

| `asset_type` | ISO 27005 | Описание | Основание |
|---|---|---|---|
| `security_appliance` | supporting | Аппаратные средства защиты информации: межсетевой экран (NGFW), IDS/IPS, VPN-шлюз, устройства WAF (сертифицированные) | 816: §7.9.2 e); 27005: A.2.2 (аппаратное обеспечение); 27001: A.8.20; ПҚ-167: §7, §12, §13 |
| `security_software` | supporting | Программные средства защиты информации: EDR, антивирус, DLP, агенты SIEM (сертифицированные) | 816: §7.9.2 e); 27005: A.2.2 (приложение); 27001: A.8.7; ПҚ-167: §7, §12, §13 |

### E.9 `personnel`

| `asset_type` | ISO 27005 | Описание | Основание |
|---|---|---|---|
| `employee` | supporting | Сотрудники организации | 816: §7.9.2 b); 27005: A.2.2 (человеческие ресурсы); 27001: A.6.1; ПҚ-167: §4 |
| `customer` | supporting | Клиенты | 816: §7.9.2 b); 27005: A.2.2 (человеческие ресурсы) |
| `user` | supporting | Пользователи (внутренние и внешние – клиенты, партнёры, пользователи Интернета) | 816: §7.9.2 b); приложение L; 27005: A.2.2 (человеческие ресурсы); 27001: A.5.18 |
| `developer` | supporting | Разработчики | 816: §7.9.2 b); 27005: A.2.2 (человеческие ресурсы); 27001: A.8.25 |
| `administrator` | supporting | Администраторы (привилегированные пользователи) | 27005: A.2.2 (человеческие ресурсы – администратор); 27001: A.8.2 |
| `responsible_person` | supporting | Лицо или подразделение, ответственное за информационную безопасность | 816: §7.15; 27005: A.2.2 (человеческие ресурсы); 27001: A.5.2; ПҚ-167: §4, §5 |

### E.10 `site`

| `asset_type` | ISO 27005 | Описание | Основание |
|---|---|---|---|
| `office_room` | supporting | Защищённые служебные помещения и переговорные | 816: §7.9.2 d); 27005: A.2.2; 27001: A.7.1 |
| `server_room` | supporting | Серверные, коммутационные помещения | 816: §7.9.2 d); 27005: A.2.2; 27001: A.7.4 |
| `backup_storage_room` | supporting | Помещения хранения резервных средств, копий и архивов (склады, архивы) | 816: §7.9.2 d); 27005: A.2.2; 27001: A.7.10 |
| `datacenter` | supporting | Центр обработки данных | 816: §7.9.2 d); 27005: A.2.2; 27001: A.7.4 |
| `passive_network_equipment` | supporting | Пассивное сетевое оборудование – монтажные шкафы, кабельные каналы, коммутационные панели | 816: §7.9.2 c)4); 27005: A.2.2 (сеть); 27001: A.7.12; ПҚ-167: §12 |

### E.11 `organization`

| `asset_type` | ISO 27005 | Описание | Основание |
|---|---|---|---|
| `supplier` | supporting | Внешний оператор или поставщик | 816: §8.6.13; 27005: A.2.2; 27001: A.5.19 |
| `org_unit` | supporting | Структурное подразделение организации (как владелец актива) | 816: §8.6.10; 27005: A.2.2; 27001: A.5.2 |

### E.12 `intangible`

| `asset_type` | ISO 27005 | Описание | Основание |
|---|---|---|---|
| `reputation` | primary | Репутация и имидж организации | 816: §7.9.2 f); 27005: A.2.2 |

---

**Контакты:** по техническим вопросам и за помощью по интеграции обращайтесь в UzCORE.
*(Контактные данные будут внесены при официальном оформлении документа.)*

