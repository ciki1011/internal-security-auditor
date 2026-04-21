# 🔐 Internal Security Auditor

> **Automated network vulnerability assessment tool** — discovers devices, detects vulnerabilities via NSE scripts, and generates prioritized PDF reports.

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: In Development](https://img.shields.io/badge/Status-In%20Development-orange.svg)]()

---

## 📋 Table of Contents

- [What Is This?](#-what-is-this)
- [Key Features](#-key-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [API Reference](#-api-reference)
- [Development Roadmap](#-development-roadmap)
- [Architecture](#-architecture)
- [Contributing](#-contributing)

---

## 🎯 What Is This?

**Internal Security Auditor** is a free, open-source tool designed for IT security professionals and network administrators who need a fast, holistic view of their internal network's security posture.

Instead of running manual scans and piecing together results from multiple tools, this system:

1. **Discovers** every active device on a subnet (ARP/ICMP sweep)
2. **Fingerprints** each device — type, OS, open ports, running services
3. **Audits** known vulnerabilities using Nmap NSE scripts mapped to CVEs
4. **Reports** everything in a clean, prioritized PDF with actionable remediation steps

**Who is it for?**
- Small-to-medium business IT teams without enterprise SIEM budgets
- Penetration testers needing rapid internal recon
- Security students building real lab experience (GNS3/VMware environments)

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔍 **Network Discovery** | ARP + ICMP sweep via Scapy — finds all live hosts in seconds |
| 🏷️ **Device Classification** | OUI lookup to identify device types (router, printer, IoT, server) |
| 🛡️ **Vulnerability Scanning** | Deep port scan + NSE script execution via python-nmap |
| 📊 **CVE Mapping** | Links discovered vulnerabilities to CVE database entries |
| 📄 **PDF Reports** | Prioritized remediation report (Critical → High → Medium → Low) |
| ⚡ **Async Architecture** | Non-blocking scans — API stays responsive during long operations |
| 🗄️ **Historical Tracking** | PostgreSQL persistence — compare network state over time |
| 🔌 **REST API** | Full OpenAPI/Swagger docs at `/docs` |

---

## 🛠️ Tech Stack

| Layer | Technology | Reason |
|---|---|---|
| **API Framework** | FastAPI 0.110+ | Async-native, automatic OpenAPI docs, fast |
| **Language** | Python 3.10+ | Match expressions, modern type hints |
| **Network Discovery** | Scapy 2.5+ | Low-level ARP/ICMP, no nmap dependency for discovery |
| **Vulnerability Scan** | python-nmap 0.7+ | NSE script execution, service fingerprinting |
| **ORM** | SQLAlchemy 2.0+ | Async-compatible, type-safe models |
| **Migrations** | Alembic | Version-controlled schema changes |
| **Database (prod)** | PostgreSQL 15+ | Reliable, JSON support for scan results |
| **Database (dev)** | SQLite | Zero-config local development |
| **Background Tasks** | FastAPI BackgroundTasks → Celery + Redis | Start simple, scale when needed |
| **PDF Generation** | WeasyPrint | HTML/CSS → PDF, easy to template |
| **Validation** | Pydantic v2 | Request/response schemas, automatic docs |
| **Testing** | pytest + httpx | Async test client for FastAPI |

---

## 📁 Project Structure

```
internal-security-auditor/
│
├── api/                          # FastAPI route handlers (thin layer — no business logic here)
│   ├── __init__.py
│   ├── routes_discovery.py       # POST /api/v1/scan/discovery
│   ├── routes_scan.py            # POST /api/v1/scan/vulnerability
│   └── routes_reports.py         # GET  /api/v1/reports/{scan_id}
│
├── core/                         # App-wide configuration and infrastructure
│   ├── __init__.py
│   ├── config.py                 # Settings via pydantic-settings (.env support)
│   ├── database.py               # SQLAlchemy engine + async session factory
│   └── security.py               # JWT auth (optional, for multi-user deployments)
│
├── models/                       # SQLAlchemy ORM models (database tables)
│   ├── __init__.py
│   ├── device.py                 # Device table
│   ├── scan_job.py               # ScanJob table
│   └── vulnerability.py          # Vulnerability table
│
├── schemas/                      # Pydantic schemas (API request/response contracts)
│   ├── __init__.py
│   ├── device.py                 # DeviceBase, DeviceCreate, DeviceRead
│   ├── scan_job.py               # ScanJobCreate, ScanJobRead, ScanJobStatus
│   └── vulnerability.py          # VulnerabilityRead, VulnerabilitySummary
│
├── services/                     # Business logic — the actual work happens here
│   ├── __init__.py
│   ├── scanner_discovery.py      # Scapy ARP/ICMP sweep + OUI classification
│   ├── scanner_nmap.py           # python-nmap NSE vulnerability scanning
│   ├── oui_lookup.py             # MAC → vendor → device type classification
│   └── report_generator.py       # WeasyPrint PDF generation
│
├── utils/                        # Shared helpers
│   ├── __init__.py
│   ├── network.py                # IP/CIDR validation, subnet utilities
│   └── cve_mapper.py             # Map NSE script output → CVE IDs + CVSS scores
│
├── migrations/                   # Alembic migration scripts
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
│       └── 001_initial_schema.py
│
├── templates/                    # HTML templates for PDF reports
│   └── report.html
│
├── tests/                        # Test suite
│   ├── __init__.py
│   ├── conftest.py               # Fixtures (test DB, test client)
│   ├── test_discovery.py
│   ├── test_scanner_nmap.py
│   └── test_reports.py
│
├── .env.example                  # Environment variable template
├── .gitignore
├── alembic.ini                   # Alembic configuration
├── main.py                       # FastAPI app initialization + lifespan
├── requirements.txt              # Production dependencies
├── requirements-dev.txt          # Development + test dependencies
├── Dockerfile                    # Container definition
├── docker-compose.yml            # PostgreSQL + Redis + app stack
├── ARCHITECTURE.md               # Deep technical documentation
└── README.md                     # This file
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- `nmap` installed on the system (`sudo apt install nmap` / `brew install nmap`)
- Root/sudo access (required for raw socket operations — ARP scanning)
- PostgreSQL (or SQLite for local dev)

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/internal-security-auditor.git
cd internal-security-auditor
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
# For development:
pip install -r requirements-dev.txt
```

### 4. Configure Environment

```bash
cp .env.example .env
# Edit .env with your database URL and settings
```

`.env.example` contents:
```env
# Application
APP_ENV=development
APP_DEBUG=true
SECRET_KEY=your-secret-key-change-in-production

# Database
DATABASE_URL=sqlite+aiosqlite:///./security_auditor.db
# For PostgreSQL:
# DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/security_auditor

# Scanning
DEFAULT_SCAN_TIMEOUT=300        # seconds
MAX_CONCURRENT_SCANS=3
```

### 5. Run Database Migrations

```bash
alembic upgrade head
```

### 6. Start the Server

```bash
# Development (with auto-reload)
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Production
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 7. Open the API Docs

Navigate to `http://localhost:8000/docs` for the interactive Swagger UI.

---

## 📡 API Reference

### Discovery Endpoints

#### `POST /api/v1/scan/discovery`
Initiates a network discovery scan (ARP/ICMP sweep).

**Request Body:**
```json
{
  "subnet": "192.168.1.0/24",
  "scan_name": "Office Network - Weekly Scan"
}
```

**Response `202 Accepted`:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "target_subnet": "192.168.1.0/24",
  "started_at": "2024-01-15T10:30:00Z",
  "status_url": "/api/v1/scan/550e8400.../status"
}
```

#### `GET /api/v1/scan/{scan_id}/status`
Poll scan status and results.

#### `GET /api/v1/devices`
List all discovered devices with their latest scan data.

### Report Endpoints

#### `GET /api/v1/reports/{scan_id}`
Download the PDF vulnerability report for a completed scan.

---

## 🗺️ Development Roadmap

### ✅ Week 1 — Foundation
- [ ] Project structure + GitHub setup
- [ ] FastAPI skeleton + database models
- [ ] Alembic migrations
- [ ] Core configuration system

### 🔄 Week 2 — Network Discovery
- [ ] Scapy ARP/ICMP sweep service
- [ ] OUI lookup + device classification
- [ ] `/api/v1/scan/discovery` endpoint
- [ ] Background task execution

### 📋 Week 3 — Vulnerability Scanning
- [ ] python-nmap integration
- [ ] NSE script orchestration
- [ ] CVE mapping utility
- [ ] Vulnerability persistence

### 📄 Week 4 — Reporting
- [ ] PDF report template (HTML/CSS)
- [ ] WeasyPrint PDF generation
- [ ] Prioritization logic (CVSS score sorting)
- [ ] Report download endpoint

### 🚀 Week 5 — Production Hardening
- [ ] Celery + Redis for async tasks
- [ ] Docker + docker-compose
- [ ] Rate limiting
- [ ] Input validation hardening

---

## 🏗️ Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for:
- Detailed component diagrams
- Database schema with ER model
- Scan lifecycle flow
- Security considerations
- Deployment options

---

## ⚠️ Legal & Ethical Use

> **This tool is intended exclusively for use on networks you own or have explicit written permission to scan.**
>
> Unauthorized network scanning may violate computer crime laws in your jurisdiction (including the Computer Fraud and Abuse Act in the US, and equivalents in the EU and Serbia).
>
> The authors accept no liability for misuse of this software.

---

## 📄 License

MIT License — free to use, modify, and distribute. See [LICENSE](LICENSE).

---

## 👤 Author

**Filip** — Security Engineer in training  
Built as part of a structured security engineering portfolio.  
Contributions and feedback welcome via GitHub Issues.
