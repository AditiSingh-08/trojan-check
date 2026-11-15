# Trojan Check

[![CI](https://github.com/AditiSingh-08/trojan-check/actions/workflows/ci.yml/badge.svg)](https://github.com/AditiSingh-08/trojan-check/actions/workflows/ci.yml)

A web app for **static triage** of suspicious files. Log in, upload an `.exe`, `.pdf`, `.doc` or `.docx`, and get a 0-100 risk score where **every point is explained by a finding**, plus file hashes, an optional VirusTotal lookup, and a downloadable PDF report.

The file is only inspected, never executed. This is a learning project and a triage aid, **not an antivirus**: a low score does not prove a file is safe.

<!-- Add 2-3 screenshots here: login, a High-risk report, a Low-risk report -->

## What it checks

| File type | Checks |
|---|---|
| **EXE / DLL** | Packer section names (UPX, ASPack, ...), per-section entropy, writable + executable sections, unusual section names, suspicious API imports grouped by behaviour, near-empty import table, forged compile timestamp, YARA rules |
| **PDF** | JavaScript, auto-run actions (`/OpenAction`, `/AA`), `/Launch`, embedded files, rich media, XFA, keywords hidden with `#xx` name encoding, encryption |
| **DOCX / DOC** | VBA macros, auto-run macro names, remote templates and other external relationships, embedded OLE/ActiveX objects, decompression-bomb detection |
| **All** | SHA-256 / SHA-1 / MD5, real file-type check from magic bytes (a `.exe` that is really a PDF is rejected), optional VirusTotal hash lookup |

### How the score works

Each finding adds points; the total is capped at 100.

| Band | Score |
|---|---|
| Low | 0-19 |
| Medium | 20-49 |
| High | 50-100 |

Examples of what adds points:

| Signal | Points |
|---|---|
| 5+ VirusTotal engines flag the file | +60 |
| Known packer section name | +25 |
| 2+ process-injection APIs imported | +25 |
| Executable section with entropy >= 7.0 | +20 |
| PDF with JavaScript | +30 (+15 if it runs automatically, +10 more together) |
| Macros inside a `.docx` | +35 |
| YARA match | +30 high / +15 medium / +5 low |

Weak signals (one debugger-check API, a single custom section name) are deliberately worth little or nothing because legitimate software triggers them too. The full rules are in `backend/scoring.py` and covered by unit tests.

## Tech stack

- **Backend:** Python, FastAPI, pefile, yara-python, PyPDF2, python-docx, python-jose (JWT), passlib/bcrypt
- **Frontend:** React, Material UI, axios, jsPDF
- **Tooling:** pytest, Jest, Docker, GitHub Actions

## Run it locally

Backend:

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows (macOS/Linux: source venv/bin/activate)
pip install -r requirements.txt
cp .env.example .env           # then edit it (optional in development)
uvicorn main:app --reload      # http://127.0.0.1:8000
```

In development the API runs without any configuration and logs in with the demo user `johndoe` / `secret`. API docs are at `http://127.0.0.1:8000/docs`.

Frontend:

```bash
cd frontend
npm install
cp .env.example .env.local
npm start                      # http://localhost:3000
```

### Configuration (environment variables)

| Variable | Purpose |
|---|---|
| `APP_ENV` | `development` (default) or `production`. Production refuses to start without `SECRET_KEY` and `DEMO_PASSWORD`. |
| `SECRET_KEY` | JWT signing key. Generate with `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `DEMO_USERNAME` / `DEMO_PASSWORD` | The single demo account (there is no user database yet). |
| `ALLOWED_ORIGINS` | Comma-separated frontend URLs allowed by CORS. |
| `MAX_FILE_SIZE_MB` | Upload limit, default 10. |
| `VT_API_KEY` | Optional. Enables the VirusTotal lookup. Only the SHA-256 is sent, never the file. |
| `REACT_APP_API_URL` | (frontend) Where the API lives. |

## Tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest

cd ../frontend
npm test
```

Backend tests cover entropy, file-type detection, scoring rules, the PDF and Office analyzers, the VirusTotal client (mocked, no network) and the API end to end.

## Docker and deployment

```bash
cp backend/.env.example backend/.env   # set APP_ENV=production, SECRET_KEY, DEMO_PASSWORD, ALLOWED_ORIGINS
docker compose up --build              # API on http://localhost:8000
```

- **API:** deploy `backend/` as a Docker service (Render, Railway, Fly.io). Set the environment variables above; the container honours `$PORT`.
- **Frontend:** deploy `frontend/` to Vercel or Netlify with `REACT_APP_API_URL` pointing at the API, then add that URL to `ALLOWED_ORIGINS`.
- The container runs as a non-root user and the app never writes uploads to disk or executes them. Still treat any public instance as handling untrusted files: keep CPU/memory limits on and don't upload sensitive documents.

## Limitations

- **Static analysis only.** Obfuscated, novel or well-packed malware can look clean; a sandbox with dynamic analysis would catch more.
- The YARA ruleset is a small hand-written starter set (`backend/rules/`), not a full signature database.
- PDF keyword scanning reads the raw file, so keywords inside compressed object streams are not seen.
- Legacy `.doc` files get a heuristic byte scan; real macro analysis needs [oletools](https://github.com/decalage2/oletools).
- Auth is a single demo account with the token stored in `localStorage`. There is no user database, registration or rate limiting yet.
- Scores are heuristics tuned by judgement, not measured against a labelled dataset.

## Roadmap

- User database and registration, scan history
- Rate limiting and a background job queue for large files
- oletools integration for macro analysis
- Evaluate the scoring against a small labelled sample set and report precision/recall
- Optional LLM-written plain-English summary of the findings (the score itself stays rule-based)

## Project structure

```
backend/
  main.py             API endpoints and request handling
  config.py           environment-based settings
  auth.py, auth_routes.py   JWT login
  filetype.py         magic-byte file-type detection
  pe_analyzer.py      PE parsing (sections, entropy, imports)
  pe_constants.py     packer names, suspicious APIs
  pdf_analyzer.py     PDF risky-feature scan
  office_analyzer.py  DOCX / DOC macro and link scan
  yara_scan.py        loads and runs rules/*.yar
  virustotal.py       optional hash lookup
  scoring.py          turns findings into score + band
  tests/              pytest suite
frontend/
  src/App.js          upload flow
  src/ReportView.js   report UI
  src/pdfReport.js    PDF export
```

Built for KrackHack 2.0 and extended afterwards.
