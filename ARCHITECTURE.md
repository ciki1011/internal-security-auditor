# 🏗️ Architecture — Internal Security Auditor

> Deep technical documentation for developers who want to understand, extend, or maintain this system.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Component Architecture](#2-component-architecture)
3. [Database Schema](#3-database-schema)
4. [Scan Lifecycle](#4-scan-lifecycle)
5. [API Layer](#5-api-layer)
6. [Service Layer](#6-service-layer)
7. [Background Task Strategy](#7-background-task-strategy)
8. [Security Considerations](#8-security-considerations)
9. [Configuration Reference](#9-configuration-reference)
10. [Extending the System](#10-extending-the-system)

---

## 1. System Overview

The Internal Security Auditor is a **service-oriented FastAPI application** with a clear separation between:

- **API Layer** — receives HTTP requests, validates input, returns responses
- **Service Layer** — executes business logic (scanning, classification, reporting)
- **Data Layer** — persists results to a relational database via SQLAlchemy

```
┌─────────────────────────────────────────────────────────┐
│                     CLIENT (Browser / curl)              │
└─────────────────────┬───────────────────────────────────┘
                      │ HTTP
┌─────────────────────▼───────────────────────────────────┐
│                  FastAPI Application                     │
│  ┌─────────────────────────────────────────────────┐    │
│  │              API Routes (api/)                  │    │
│  │  routes_discovery.py  │  routes_reports.py      │    │
│  └──────────────┬──────────────────────────────────┘    │
│                 │ calls                                  │
│  ┌──────────────▼──────────────────────────────────┐    │
│  │           Service Layer (services/)              │    │
│  │  scanner_discovery.py  │  scanner_nmap.py        │    │
│  │  oui_lookup.py         │  report_generator.py    │    │
│  └──────────────┬──────────────────────────────────┘    │
│                 │ reads/writes                           │
│  ┌──────────────▼──────────────────────────────────┐    │
│  │         Data Layer (models/ + database)          │    │
│  │  Device  │  ScanJob  │  Vulnerability            │    │
│  └──────────────┬──────────────────────────────────┘    │
└─────────────────┼───────────────────────────────────────┘
                  │
         ┌────────▼────────┐
         │   PostgreSQL /   │
         │     SQLite       │
         └─────────────────┘

External Dependencies:
  [Scapy] ←── scanner_discovery.py (raw sockets, ARP/ICMP)
  [nmap]  ←── scanner_nmap.py (subprocess + python-nmap wrapper)
  [OUI DB]←── oui_lookup.py (local IEEE OUI database file)
```

---

## 2. Component Architecture

### 2.1 API Layer (`api/`)

Routes are **thin**. They do three things only:
1. Parse and validate the incoming request (via Pydantic schemas)
2. Call the appropriate service
3. Return the response

No business logic lives in routes. A route that does more than ~20 lines of logic needs to be refactored — move the logic to `services/`.

```python
# Correct pattern — api/routes_discovery.py
@router.post("/discovery", response_model=ScanJobRead, status_code=202)
async def start_discovery(
    payload: ScanJobCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    scan_job = await create_scan_job(db, payload)
    background_tasks.add_task(run_discovery_scan, scan_job.id, payload.subnet)
    return scan_job
```

### 2.2 Service Layer (`services/`)

This is where the real work happens. Each service file has a single responsibility:

| File | Responsibility |
|---|---|
| `scanner_discovery.py` | ARP sweep → live host list |
| `scanner_nmap.py` | Deep port scan + NSE scripts |
| `oui_lookup.py` | MAC address → device type classification |
| `report_generator.py` | Compile scan data → PDF report |

### 2.3 Models vs Schemas

This distinction is critical and often confused by newcomers:

| | Models (`models/`) | Schemas (`schemas/`) |
|---|---|---|
| **Technology** | SQLAlchemy | Pydantic |
| **Purpose** | Defines database tables | Defines API contracts |
| **Used for** | ORM queries, persistence | Request validation, response serialization |
| **Lives in** | Database | HTTP layer only |

**Rule:** Never return a SQLAlchemy model object directly from a route. Always convert to a Pydantic schema first.

---

## 3. Database Schema

### 3.1 Entity-Relationship Diagram

```
┌─────────────────────┐        ┌──────────────────────────┐
│       Device        │        │         ScanJob           │
├─────────────────────┤        ├──────────────────────────┤
│ id          UUID PK │        │ id             UUID PK   │
│ ip_address  String  │        │ target_subnet  String    │
│ mac_address String  │        │ status         Enum      │
│ hostname    String? │        │ scan_name      String?   │
│ device_type String  │        │ started_at     DateTime  │
│ os_guess    String? │        │ finished_at    DateTime? │
│ first_seen  DateTime│        │ devices_found  Integer   │
│ last_seen   DateTime│        │ error_message  Text?     │
└──────┬──────────────┘        └──────────────────────────┘
       │ 1
       │ has many
       │ N
┌──────▼──────────────┐
│    Vulnerability     │
├─────────────────────┤
│ id           UUID PK│
│ device_id    FK     │ ─── references Device.id
│ cve_id       String │  (e.g. "CVE-2021-44228")
│ severity     Enum   │  (Critical/High/Medium/Low/Info)
│ cvss_score   Float? │  (0.0 – 10.0)
│ description  Text   │
│ port         Integer│  (affected port)
│ service      String │  (e.g. "ssh", "http")
│ nse_script   String │  (script that found it)
│ remediation  Text?  │  (recommended fix)
│ discovered_at DateTime│
└─────────────────────┘
```

### 3.2 SQLAlchemy Model — Device

```python
# models/device.py
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from core.database import Base

class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    ip_address: Mapped[str] = mapped_column(String(45))       # IPv4 or IPv6
    mac_address: Mapped[str] = mapped_column(String(17), unique=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    device_type: Mapped[str] = mapped_column(String(50), default="Unknown")
    os_guess: Mapped[str | None] = mapped_column(String(100))
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
```

### 3.3 Enum Values

**ScanJob.status:**
- `pending` — created, not yet started
- `running` — actively scanning
- `completed` — finished successfully
- `failed` — terminated with error

**Vulnerability.severity** (maps to CVSS v3 ranges):
- `critical` — CVSS 9.0–10.0
- `high` — CVSS 7.0–8.9
- `medium` — CVSS 4.0–6.9
- `low` — CVSS 0.1–3.9
- `info` — informational, no CVSS score

---

## 4. Scan Lifecycle

### 4.1 Discovery Scan Flow

```
Client                    FastAPI              BackgroundTask          Database
  │                          │                      │                      │
  │  POST /scan/discovery     │                      │                      │
  │  { subnet: "x.x.x.0/24" }│                      │                      │
  │─────────────────────────►│                      │                      │
  │                          │ validate input        │                      │
  │                          │ create ScanJob (status=pending)              │
  │                          │─────────────────────────────────────────────►│
  │                          │ enqueue background task                      │
  │                          │─────────────────────►│                      │
  │  202 Accepted             │                      │                      │
  │  { scan_id, status_url } │                      │                      │
  │◄─────────────────────────│                      │                      │
  │                          │                      │ update status=running│
  │                          │                      │─────────────────────►│
  │                          │                      │ Scapy ARP sweep      │
  │                          │                      │ (sends ARP requests  │
  │                          │                      │  to all /24 hosts)   │
  │                          │                      │ collect responses    │
  │                          │                      │ OUI lookup per MAC   │
  │                          │                      │ upsert Devices       │
  │                          │                      │─────────────────────►│
  │                          │                      │ update status=completed
  │                          │                      │─────────────────────►│
  │                          │                      │                      │
  │  GET /scan/{id}/status   │                      │                      │
  │─────────────────────────►│                      │                      │
  │                          │ query ScanJob        │                      │
  │                          │─────────────────────────────────────────────►│
  │  200 OK                  │                      │                      │
  │  { status: "completed",  │                      │                      │
  │    devices: [...] }      │                      │                      │
  │◄─────────────────────────│                      │                      │
```

### 4.2 ARP Sweep — How It Works

Scapy sends an Ethernet broadcast frame with an ARP request to every IP in the subnet. Hosts that are alive respond with their MAC address. This is faster and more reliable than ICMP ping (which firewalls often block).

```python
# Simplified pseudocode — services/scanner_discovery.py
def arp_sweep(subnet: str) -> list[dict]:
    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, _ = srp(packet, timeout=2, verbose=False)

    results = []
    for sent, received in answered:
        results.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
        })
    return results
```

### 4.3 OUI Classification Logic

IEEE assigns the first 3 bytes (24 bits) of every MAC address to a specific vendor (e.g., `00:1A:2B` → Cisco Systems). We use this to make an educated guess about device type:

```
MAC: B8:27:EB:xx:xx:xx
       └── OUI lookup → "Raspberry Pi Foundation"
                              └── device_type = "IoT / Single Board Computer"

MAC: 00:1A:2B:xx:xx:xx
       └── OUI lookup → "Cisco Systems"
                              └── device_type = "Network Equipment (Router/Switch)"
```

The OUI database is downloaded from the IEEE registry and stored locally as a SQLite lookup table for fast, offline resolution.

---

## 5. API Layer

### 5.1 Versioning

All routes are prefixed with `/api/v1/`. Future breaking changes will use `/api/v2/` while maintaining backward compatibility.

### 5.2 Endpoint Map

```
POST   /api/v1/scan/discovery          → Start network discovery scan
POST   /api/v1/scan/vulnerability      → Start vulnerability scan on specific device(s)
GET    /api/v1/scan/{scan_id}/status   → Get scan status + results
GET    /api/v1/devices                 → List all known devices
GET    /api/v1/devices/{device_id}     → Get single device + all vulnerabilities
GET    /api/v1/reports/{scan_id}       → Download PDF report
GET    /api/v1/health                  → Health check (for monitoring)
```

### 5.3 Response Conventions

All responses follow these conventions:

- **202 Accepted** — for operations that start a background task
- **200 OK** — for reads and completed synchronous operations
- **404 Not Found** — when a scan_id or device_id doesn't exist
- **422 Unprocessable Entity** — when request body validation fails (automatic via Pydantic)
- **503 Service Unavailable** — when nmap is not installed on the system

Error responses always include:
```json
{
  "detail": "Human-readable error message",
  "error_code": "MACHINE_READABLE_CODE"
}
```

---

## 6. Service Layer

### 6.1 scanner_discovery.py

**Inputs:** subnet string (e.g. `"192.168.1.0/24"`)  
**Outputs:** list of `DiscoveredHost` dataclasses  
**Side effects:** writes to `Device` table (upsert by MAC address)

Key design decision: we **upsert** by MAC address, not IP. IP addresses can change (DHCP), but MAC addresses are stable on a local network. When we see a known MAC with a new IP, we update `ip_address` and `last_seen` rather than creating a duplicate device record.

### 6.2 scanner_nmap.py

**Inputs:** list of IP addresses, scan profile  
**Outputs:** list of `VulnerabilityFound` dataclasses  
**Side effects:** writes to `Vulnerability` table, updates `Device.os_guess`

NSE scripts we run (configurable via scan profiles):

| Script | Detects |
|---|---|
| `vuln` | General vulnerability scan (includes many CVEs) |
| `smb-vuln-ms17-010` | EternalBlue (CVE-2017-0144) — WannaCry vector |
| `http-shellshock` | Shellshock (CVE-2014-6271) |
| `ssl-heartbleed` | Heartbleed (CVE-2014-0160) |
| `ftp-anon` | Anonymous FTP access |
| `ssh-auth-methods` | Weak SSH authentication |

### 6.3 report_generator.py

Takes a completed `ScanJob` with all related `Device` and `Vulnerability` records, renders an HTML template with Jinja2, and converts to PDF via WeasyPrint.

Report sections:
1. Executive Summary (device count, vulnerability count by severity)
2. Risk Matrix (visual grid of severity × likelihood)
3. Prioritized Findings (Critical first, with CVE links and remediation)
4. Full Device Inventory
5. Methodology appendix

---

## 7. Background Task Strategy

### Phase 1 (current): FastAPI BackgroundTasks

Simple, no extra infrastructure. Runs in the same process as the API server. Fine for:
- Development
- Single-server deployments
- Scans that complete in < 5 minutes

**Limitation:** if the server restarts while a scan is running, the task is lost.

### Phase 2 (future): Celery + Redis

When we need:
- Scan persistence across restarts
- Multiple worker processes
- Task queuing (prevent 10 simultaneous nmap scans from killing the server)
- Retry logic on failure

Migration path: the service functions (`run_discovery_scan`, `run_vulnerability_scan`) are already written as plain async functions. To move to Celery, we wrap them with `@celery_app.task` — no other code changes needed.

---

## 8. Security Considerations

### 8.1 Who Should Run This?

This tool requires elevated privileges (raw sockets for ARP scanning). Deployment options:

- **Single trusted user** — run as root locally (development/lab)
- **Internal tool** — deploy behind internal network only, add JWT auth
- **Multi-user** — add per-user API keys, audit logging, rate limiting

### 8.2 Input Validation

All subnet inputs are validated before any scanning begins:

```python
# utils/network.py
import ipaddress

def validate_subnet(subnet: str) -> bool:
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        # Reject subnets larger than /16 (65535 hosts) to prevent abuse
        if network.num_addresses > 65536:
            raise ValueError("Subnet too large. Maximum /16 supported.")
        return True
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
```

### 8.3 What This Tool Does NOT Do

- Does not perform exploitation (read-only vulnerability detection)
- Does not exfiltrate data outside the local network
- Does not store plaintext credentials
- Does not scan external (internet) IP ranges (blocked by validation)

---

## 9. Configuration Reference

All configuration is managed via `core/config.py` using `pydantic-settings`. Values are loaded from environment variables or `.env` file.

| Variable | Type | Default | Description |
|---|---|---|---|
| `APP_ENV` | string | `development` | `development` or `production` |
| `APP_DEBUG` | bool | `false` | Enable debug logging |
| `DATABASE_URL` | string | SQLite | SQLAlchemy async connection URL |
| `SECRET_KEY` | string | **required** | JWT signing key (32+ chars) |
| `DEFAULT_SCAN_TIMEOUT` | int | `300` | Max seconds per scan before timeout |
| `MAX_CONCURRENT_SCANS` | int | `3` | Prevent resource exhaustion |
| `OUI_DB_PATH` | string | `./data/oui.db` | Path to local OUI database |
| `REPORT_OUTPUT_DIR` | string | `./reports/` | Where to save generated PDFs |

---

## 10. Extending the System

### Adding a New NSE Script

1. Add the script name to `services/scanner_nmap.py` in the `NSE_SCRIPTS` list
2. Add a mapping in `utils/cve_mapper.py` from script output patterns to CVE IDs
3. Add a test case in `tests/test_scanner_nmap.py`

### Adding a New Device Classification Rule

Edit `services/oui_lookup.py` and add to the `VENDOR_TYPE_MAP` dictionary:

```python
VENDOR_TYPE_MAP = {
    "Raspberry Pi": "IoT / Single Board Computer",
    "Cisco": "Network Equipment",
    "HP": "Workstation / Printer",
    # Add new rules here
    "YourVendor": "Your Device Type",
}
```

### Adding a New Report Section

1. Edit `templates/report.html` to add the HTML structure
2. Update `services/report_generator.py` to pass the new data to the template context
3. Update the relevant Pydantic schema if new fields are needed

---

## Handoff Checklist

If you're picking up this project from the original author, make sure you:

- [ ] Read this document fully before writing code
- [ ] Run `alembic upgrade head` after cloning
- [ ] Copy `.env.example` to `.env` and fill in values
- [ ] Check that `nmap` is installed: `nmap --version`
- [ ] Run the test suite: `pytest tests/ -v`
- [ ] Read `CONTRIBUTING.md` for branch naming and commit conventions

---

*Last updated: 2026 | Maintained by Filip*