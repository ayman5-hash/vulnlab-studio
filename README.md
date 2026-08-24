# VulnLab Studio

VulnLab Studio is a controlled web-security research and training platform combining:

- an intentionally vulnerable Flask application;
- a FastAPI vulnerability scanner;
- Black Box and White Box assessment modes;
- six detection modules;
- multiple difficulty levels;
- persistent scan history;
- security scoring;
- PDF reporting;
- a Next.js security dashboard.

> **Warning**
>
> VulnLab contains intentionally vulnerable components.
> Run it only inside an isolated and explicitly authorized laboratory.

## Architecture

```text
                 ┌─────────────────────┐
                 │   VulnLab Studio    │
                 │   Next.js :3000     │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │    Scanner API      │
                 │   FastAPI :8000     │
                 └──────────┬──────────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
          ▼                 ▼                 ▼
       Crawler          Detectors         White Box
                            │
        XSS - SQLi - LFI - Traversal - RFI - Auth
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Vulnerable Target   │
                 │   Flask :8080       │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Controlled Resource │
                 │ Server :9000        │
                 └─────────────────────┘
```

## Components

| Component | Technology | Address |
|---|---|---|
| Security Studio | Next.js / React | http://127.0.0.1:3000 |
| Scanner API | FastAPI | http://127.0.0.1:8000 |
| Vulnerable Target | Flask | http://127.0.0.1:8080 |
| Controlled Resource Server | Python HTTP Server | http://127.0.0.1:9000 |

## Detection Modules

- Cross-Site Scripting (XSS)
- SQL Injection (SQLi)
- Local File Inclusion (LFI)
- Path Traversal
- Controlled Remote Resource Inclusion behavior
- Authentication / brute-force resistance assessment

## Difficulty Levels

VulnLab supports four laboratory levels:

- Easy
- Medium
- Hard
- Expert

## Assessment Modes

### Black Box

Assessment based on externally observable application behavior.

### White Box

Dynamic assessment combined with lightweight static source-code correlation against an explicitly authorized local source directory.

## Project Structure

```text
vulnlab/
├── frontend/
├── scanner/
│   └── app/
│       ├── detectors/
│       └── reporting/
├── vulnerable-app/
├── resource-server/
├── reports/
├── scripts/
├── tests/
├── README.md
├── SECURITY.md
└── .gitignore
```

## Starting the Vulnerable Application

```bash
cd vulnerable-app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Target:

```text
http://127.0.0.1:8080
```

## Starting the Controlled Resource Server

```bash
cd resource-server
python3 -m http.server 9000 --bind 127.0.0.1
```

## Starting the Scanner API

```bash
cd scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

## Starting the Security Studio

```bash
cd frontend
npm install
npm run dev -- --hostname 127.0.0.1 --port 3000
```

Open:

```text
http://127.0.0.1:3000
```

## PDF Reporting

Persisted assessments can be exported through:

```text
GET /reports/{scan_id}
```

Reports contain assessment metadata, security scoring, findings, severity, confidence, CWE references, evidence, recommendations, and White Box correlations when applicable.

## Safety

VulnLab is intended exclusively for controlled cybersecurity education and authorized security research.

Do not assess systems without explicit authorization.

Do not expose the intentionally vulnerable Flask application directly to the public Internet.

See `SECURITY.md`.
