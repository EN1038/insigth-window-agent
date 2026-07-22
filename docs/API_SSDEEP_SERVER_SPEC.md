# สเปก API สำหรับทีม Server (ssdeep + โฟลวที่ยังขาด)

**โปรเจกต์:** SOSECURE Threat inSight — Go Agent  
**วันที่:** 2026-07-21  
**ผู้จัดทำ:** จากสเปก agent ปัจจุบัน (`go-agent/internal/api/client.go`)

---

## ข้อตกลงทั่วไป (เหมือน API เดิม)

- **URL:** `POST {SiteIP}/api/{SiteID}/agentClient/{endpoint}`
- **Header:** `Authorization: Bearer {SiteKey}`, `Content-Type: application/json`
- **Response (แนะนำให้คงแบบเดิม):**

```json
{
  "error": "",
  "status_code": 200,
  "data": { }
}
```

`status_code != 200` หรือ `error` ไม่ว่าง = ล้มเหลว

---

## A) API เดิมที่ Agent ใช้อยู่แล้ว (ไม่ต้องเปลี่ยน schema)

| Endpoint | หมายเหตุ |
|----------|----------|
| `dataInfo`, `loginAgent`, `checkedAgentApproved` | ลงทะเบียน / approve |
| `getConfig`, `updateConfig` | config เครื่อง |
| `getRule`, `downloadRuleSite`, `downloadRuleSiteComplete`, `updateRuleDownload` | YARA |
| `agentOnlineTimestamp` | heartbeat |
| `sendLogYara` | เฉพาะ detection **engine = yara** |
| `sendHash` | MD5 เฉพาะไฟล์ที่เจอจาก **YARA** |
| `sendAgentScanLog` | เริ่ม/จบสแกน (ข้อความใน `description` มี `yara=N ssdeep=M` ตอนจบ) |

---

## B) API ใหม่ที่ Server ต้องทำ (ครบโฟลว ssdeep)

ลำดับความสำคัญ:

1. **`sendLogSsdeep`** — บังคับก่อน (Agent เรียกแล้ว)
2. ชุดซิงก์ฐาน — mirror YARA
3. **`sendSsdeepCandidate`** — โฟลว VT / เติมฐานกลาง
4. ขยาย **`getConfig`** — คุม policy จาก server

---

### 1) `sendLogSsdeep` — รายงาน fuzzy hash + metadata (แยกจาก YARA)

**วัตถุประสงค์:** เก็บ log การเจอ malware พร้อม **ssdeep fuzzy hash** ทั้งกรณีเจอจาก YARA และ ssdeep โดยไม่แตะ `sendLogYara` / `sendHash`

**Request body:**

```json
{
  "ssdeep": [
    {
      "agent_id": 12345,
      "path": "C:\\Users\\x\\Downloads\\evil.exe",
      "file_name": "evil.exe",
      "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
      "ssdeep": "3072:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/|1234567890",
      "engine": "yara",
      "rule": "Win.Trojan.Something",
      "score": 0,
      "description": "Malware detected: Win.Trojan.Something",
      "device_name": "DESKTOP-ABC",
      "detected_at": "2026-07-21 14:30:00"
    },
    {
      "agent_id": 12345,
      "path": "C:\\temp\\a.exe",
      "file_name": "a.exe",
      "hash_md5": "",
      "ssdeep": "3072:...",
      "engine": "ssdeep",
      "rule": "ssdeep:Emotet@92",
      "score": 92,
      "description": "Ssdeep similarity match: ssdeep:Emotet@92 (score=92)",
      "device_name": "DESKTOP-ABC",
      "detected_at": "2026-07-21 14:31:00"
    }
  ]
}
```

| Field | ชนิด | บังคับ | ความหมาย |
|-------|------|--------|----------|
| `agent_id` | int64 | ใช่ | จาก `getConfig.agent.id` |
| `path` | string | ใช่ | path เต็มบนเครื่องลูกข่าย |
| `file_name` | string | ใช่ | ชื่อไฟล์ |
| `hash_md5` | string | ไม่ | ว่างได้ถ้าอ่าน MD5 ไม่ได้ |
| `ssdeep` | string | ใช่ | fuzzy hash เต็มรูปแบบ ssdeep |
| `engine` | string | ใช่ | `"yara"` หรือ `"ssdeep"` |
| `rule` | string | ใช่ | ชื่อ YARA rule หรือ `ssdeep:{name}@{score}` |
| `score` | int | ไม่ | ใส่เมื่อ `engine=ssdeep` (ความคล้าย 0–100) |
| `description` | string | ใช่ | ข้อความสรุป |
| `device_name` | string | ใช่ | hostname |
| `detected_at` | string | ใช่ | `YYYY-MM-DD HH:MM:SS` (local agent) |

**Response `data` (แนะนำ):**

```json
{
  "accepted": 2,
  "ids": [1001, 1002]
}
```

**พฤติกรรม Agent:** ส่งเมื่อ `ssdeep_report_api=true` (default) และคำนวณ fuzzy ได้; **ไม่** ส่ง ssdeep-only ไป `sendLogYara`/`sendHash`

---

### 2) `getSsdeep` — metadata ฐานลายเซ็น (เทียบ `getRule`)

**Request:**

```json
{
  "ip_private": "192.168.1.10"
}
```

**Response `data` (แนะนำ):**

```json
{
  "ssdeep_db": {
    "version": "2026.07.21.1",
    "signature_count": 777685,
    "updated_at": "2026-07-21T08:00:00Z",
    "min_agent_build": "1.0.0"
  }
}
```

Agent ใช้เทียบกับ `ssdeep_db_version` ใน settings ว่าต้องดาวน์โหลดใหม่หรือไม่

---

### 3) `downloadSsdeepSite` — รายการไฟล์ให้ดาวน์โหลด (เทียบ `downloadRuleSite`)

**Request:**

```json
{
  "ip_private": "192.168.1.10",
  "current_version": "2026.07.20.1"
}
```

**Response `data`:** array หรือ `{ "signatures": [ ... ] }` (Agent รองรับทั้ง array ตรงและ nested แบบ YARA)

```json
{
  "signatures": [
    {
      "id": 501,
      "path": "https://{SiteIP}/storage/ssdeep/signatures_20260721.db.zip",
      "file_name": "signatures_20260721.db.zip",
      "version": "2026.07.21.1",
      "format": "sqlite_zip",
      "sha256": "abc...",
      "size_bytes": 140000000
    }
  ]
}
```

| Field | ความหมาย |
|-------|----------|
| `id` | id ชุดดาวน์โหลด (ใช้ complete / update) |
| `path` | URL เต็ม หรือ path ขึ้นต้น `/` (Agent ต่อกับ `SiteIP` + Bearer เหมือน YARA) |
| `format` | `sqlite_zip` \| `sqlite` \| `json` (แนะนำ `sqlite_zip` = `signatures.db` ใน zip) |
| `version` | เวอร์ชันฐานหลัง import |

**ฝั่ง Server:** ไฟล์ควรเป็น schema เดียวกับ `signatures.db` ที่ agent import อยู่ (`malware_name`, `ssdeep_full`, `block_size` ฯลฯ)

---

### 4) `downloadSsdeepSiteComplete` — ยืนยันดาวน์โหลดสำเร็จ

**Request:**

```json
{
  "id": 501
}
```

**Response:** `status_code: 200`, `data` ว่างหรือ `{ "ok": true }`

---

### 5) `updateSsdeepDownload` — บันทึกว่า agent รับชุดนี้แล้ว (เทียบ `updateRuleDownload`)

**Request:**

```json
{
  "agent_id": 12345,
  "ssdeep_id": 501,
  "version": "2026.07.21.1"
}
```

**Response:** `status_code: 200`

---

### 6) `sendSsdeepCandidate` — ส่งตัวอย่างเข้าคิว VT / review (โฟลวเติมฐาน)

**วัตถุประสงค์:** เมื่อเจอของใหม่ / fuzzy ที่อยากเก็บ — server คิว VT แล้วค่อย merge เข้า `signatures`

**Request:**

```json
{
  "ip_private": "192.168.1.10",
  "candidates": [
    {
      "agent_id": 12345,
      "path": "C:\\Users\\x\\file.exe",
      "file_name": "file.exe",
      "hash_md5": "...",
      "hash_sha256": "...",
      "ssdeep": "3072:...",
      "engine": "yara",
      "rule": "Win.Trojan.X",
      "score": 0,
      "scan_mode": "MANUAL_SCAN",
      "detected_at": "2026-07-21 14:30:00",
      "source": "agent_detection"
    }
  ]
}
```

| Field | บังคับ | หมายเหตุ |
|-------|--------|----------|
| `hash_sha256` | แนะนำ | ใช้คิว VT ฝั่ง server |
| `scan_mode` | แนะนำ | เหมือน `sendAgentScanLog.mode`: `MANUAL_SCAN`, `AUTO_SCAN`, `USB_SCAN`, `REALTIME_SCAN`, `CUSTOM_SCAN` |
| `source` | ไม่ | เช่น `agent_detection`, `yara_hit`, `ssdeep_hit` |

**Response `data`:**

```json
{
  "accepted": 1,
  "queue_ids": [9001]
}
```

**หมายเหตุ:** Agent **ยังไม่เรียก** endpoint นี้ — ต้อง implement ฝั่ง server ก่อน แล้วค่อย wire ใน agent (อาจส่งคู่กับ `sendLogSsdeep` หรือแยกตาม policy)

---

### 7) ขยาย `getConfig` (ไม่ใช่ path ใหม่ — แต่จำเป็นสำหรับโฟลวครบ)

เพิ่มใน `data` ที่ส่งกลับ (Agent จะอ่านเมื่อ implement ตามนี้):

```json
{
  "agent": { "id": 12345 },
  "real_time_protection": 1,
  "usb_protection": 1,
  "batchjob_everydate": "02:00",
  "scan_extensions": [".exe", ".dll"],
  "ssdeep_enabled": 1,
  "ssdeep_threshold": 85,
  "ssdeep_report_api": 1,
  "ssdeep_db_version": "2026.07.21.1",
  "quarantine_on_detect": 1,
  "send_ssdeep_candidate": 1
}
```

| Field | ค่า | ความหมาย |
|-------|-----|----------|
| `ssdeep_enabled` | 0/1 | เปิดชั้น ssdeep หลัง YARA |
| `ssdeep_threshold` | 0–100 | คะแนนขั้นต่ำ |
| `ssdeep_report_api` | 0/1 | อนุญาต `sendLogSsdeep` |
| `ssdeep_db_version` | string | เทียบกับเครื่อง → trigger `downloadSsdeepSite` |
| `quarantine_on_detect` | 0/1 | 0 = แจ้งเตือนอย่างเดียว (อนาคต) |
| `send_ssdeep_candidate` | 0/1 | ให้ agent เรียก `sendSsdeepCandidate` |

---

### 8) (ทางเลือก) ขยาย `sendAgentScanLog` — สรุปตัวเลขแบบ structured

ตอนนี้ Agent ส่งแค่ข้อความใน `description` เช่น `threats (yara=2 ssdeep=1)`  
ถ้าต้องการ query บน DB แนะนำเพิ่มฟิลด์ในแต่ละ item (backward compatible):

```json
{
  "agent_scan": [
    {
      "agent_id": 12345,
      "description": "Scan completed: 50000 files, 3 threats (yara=2 ssdeep=1)",
      "time_stamp": "2026-07-21 15:00:00",
      "mode": "MANUAL_SCAN",
      "type": "end",
      "files_total": 50000,
      "files_scanned": 48000,
      "files_skipped": 2000,
      "threats_total": 3,
      "threats_yara": 2,
      "threats_ssdeep": 1,
      "status": "completed"
    }
  ]
}
```

ฟิลด์ใหม่เป็น **optional** — ถ้า server ยังไม่รองรับ ใช้ parse จาก `description` ได้

---

## C) โฟลวรวม (ให้ Server ออกแบบร่วมกัน)

```
[Agent approve แล้ว]
    → getConfig (+ ssdeep_db_version, threshold, flags)
    → getSsdeep / downloadSsdeepSite (ถ้า version เก่ากว่า)
    → GET ไฟล์ signatures (Bearer) → import → downloadSsdeepSiteComplete + updateSsdeepDownload

[ระหว่างสแกน]
    → sendAgentScanLog (start/end)
    → YARA hit → sendLogYara + sendHash
    → ทุก hit ที่มี fuzzy → sendLogSsdeep
    → (ถ้าเปิด) sendSsdeepCandidate

[Server]
    → เก็บ log / dashboard
    → VT worker จาก candidate
    → อัปเดต signatures DB → version ใหม่ → agent ดึงรอบถัดไป
```

---

## D) Checklist ส่งให้ทีม Server

| # | Endpoint / งาน | Agent วันนี้ | Server ต้องทำ |
|---|----------------|--------------|---------------|
| 1 | `sendLogSsdeep` | เรียกแล้ว | **ต้องทำก่อน** |
| 2 | `getSsdeep` | ยังไม่เรียก | ทำ + agent จะตาม |
| 3 | `downloadSsdeepSite` | ยังไม่เรียก | ทำ |
| 4 | `downloadSsdeepSiteComplete` | ยังไม่เรียก | ทำ |
| 5 | `updateSsdeepDownload` | ยังไม่เรียก | ทำ |
| 6 | `sendSsdeepCandidate` | ยังไม่เรียก | ทำ (ถ้ามี VT pipeline) |
| 7 | ขยาย `getConfig` | อ่านบางฟิลด์เดิม | เพิ่ม ssdeep/quarantine flags |
| 8 | `sendAgentScanLog` ฟิลด์ตัวเลข | ส่งแค่ text | optional |

---

## E) สิ่งที่ตั้งใจไม่ส่งผ่าน API เดิม

- **ไม่** ใส่ `ssdeep` / `engine` ใน `sendHash`
- **ไม่** ใส่ ssdeep metadata ใน `sendLogYara` สำหรับ detection แบบ ssdeep-only
- ทุกอย่างเกี่ยว fuzzy + ssdeep engine → **`sendLogSsdeep`** (+ candidate แยก)

---

## F) สถานะโปรแกรม Agent (อ้างอิง)

### โฟลวสแกนไฟล์

1. รวบรวมไฟล์ตามโหมดสแกน
2. **YARA** ทุกไฟล์ใน batch
3. ไฟล์ที่ YARA **ไม่เจอ** → **ssdeep** (ถ้าเปิด + ผ่านขนาด/นามสกุล)
4. เจอภัย → quarantine + ส่ง API ตาม engine
5. จบสแกน → `sendAgentScanLog` (end)

### โหมดสแกน

| โหมด | ทริกเกอร์ |
|------|-----------|
| Quick / Full / Custom | UI / IPC |
| Scheduled | รายวันตาม `batchjob_everydate` |
| Realtime | ไฟล์ใหม่ใน Downloads/Desktop |
| USB | ไดรฟ์ removable ใหม่ |

### การส่ง API เมื่อเจอภัย

| Engine | sendLogYara | sendHash | sendLogSsdeep |
|--------|-------------|----------|---------------|
| YARA | ส่ง | ส่ง (MD5) | ส่ง fuzzy (ถ้า hash ได้) |
| ssdeep | ไม่ส่ง | ไม่ส่ง | ส่ง |

---

*เอกสารนี้สอดคล้องกับโค้ด agent ใน `go-agent/internal/api/client.go` และ `go-agent/internal/scan/manager.go`*
