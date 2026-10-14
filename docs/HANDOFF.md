# AI-TIP Handoff Documentation

## 1. Project Overview

AI-TIP (AI-Third-Party Intelligence Platform) is a comprehensive cybersecurity platform for monitoring third-party vendor risks, CVE correlations, and threat intelligence analysis. The platform provides enterprise SOC dashboards, automated risk assessments, and AI-powered insights.

**Architecture Flow:**
```
Customer → Customer Vendors → Vendor Architecture → Technologies/Services/External Assets 
→ Threat Intelligence → Correlation → Risk Assessment → Alerts/Exposures → Dashboard/Reports/AI Assistant
```

## 2. Architecture

**Backend (FastAPI):**
- REST API with JWT authentication
- PostgreSQL database with 35+ tables
- APScheduler for periodic threat intelligence collection
- Ollama integration for AI assistant (Graph RAG)
- Email notifications via Resend
- MITRE ATT&CK correlation engine

**Frontend (React + Vite):**
- React 19 with TypeScript
- Tailwind CSS for styling
- shadcn/ui components
- Recharts for data visualization
- Lucide React icons

**Database:**
- PostgreSQL 14+
- Schema: `database/ai_tip_schema.sql` (clean)
- Historical reference export: `database/ai_tip_dump.sql` (not used for setup)

## 3. Requirements

**Software:**
- PostgreSQL 14+
- Python 3.11+ (tested with 3.14)
- Node.js 18+
- Ollama (optional, for AI features)

**Python Dependencies:**
- FastAPI, uvicorn
- psycopg2-binary
- APScheduler
- bcrypt
- python-multipart
- PyPDF2
- numpy

**Node Dependencies:**
- React, Vite
- Tailwind CSS
- recharts
- lucide-react
- react-router-dom

## 4. Environment Configuration

Create `backend/.env`:

```env
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=ai_tip
DB_USER=postgres
DB_PASSWORD=your_password

# JWT
SECRET_KEY=your-secret-key
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Ollama (optional)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:0.5b

# Resend Email (optional)
RESEND_API_KEY=your_resend_api_key
RESEND_FROM=onboarding@resend.dev
```

**Note:** Never commit `.env` files or actual credentials to version control.

## 5. Database Setup

Create `backend/.env` from `backend/.env.example` and set the database password.
Then, from the repository root in PowerShell:

```powershell
python backend/scripts/setup_database.py
```

This is the authoritative deployment method. It creates a fresh database from
`database/ai_tip_schema.sql`, seeds labelled demo data, aligns sequences, and
validates critical tables, relationships, and seed data. It requires no `psql`
binary and never changes an existing database.

To intentionally recreate an existing **development** database:

```powershell
python backend/scripts/setup_database.py --reset --yes
```

`database/ai_tip_dump.sql` remains a historical/reference export only. It is
not the authoritative handoff artifact because it is missing architecture
tables required by the current application.

**Demo User Accounts:**
| Email | Password | Role |
|-------|----------|------|
| admin@example.com | admin | Admin |
| analyst@example.com | Analyst123! | Analyst |
| viewer@example.com | Viewer123! | Viewer |

## 6. Backend Startup

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
.venv\Scripts\python -m uvicorn app.main:app --reload --port 8000
```

API Documentation: http://localhost:8000/docs

## 7. Frontend Startup

```bash
cd frontend
npm install
npm run dev
```

Frontend: http://localhost:5173

## 8. Test Command

**Backend Tests:**
```bash
cd backend
.venv\Scripts\python -m pytest tests/ -v --tb=short
```

Verified closeout result: 115 passed, 0 failed, 0 skipped.

**Frontend Build:**
```bash
cd frontend
npm run build
```

## 9. Optional Integrations

**NVD (CVE):**
- No API key required
- Automatically fetches CVE data

**HIBP (Have I Been Pwned):**
- Requires `HIBP_API_KEY` in `.env`
- Optional - application works without it

**Resend (Email):**
- Requires `RESEND_API_KEY` in `.env`
- Optional - email notifications disabled without it

**Ollama (AI Assistant):**
- Requires local Ollama service
- Models: `qwen2.5:0.5b`, `nomic-embed-text`
- Optional - application works without it

## 10. Known Limitations

- **APScheduler:** In-memory job storage - jobs reset on application restart
- **HIBP:** Requires API key for breach intelligence
- **Ollama:** Requires local service for AI features
- **Historical dump:** `database/ai_tip_dump.sql` is retained for reference only; use `backend/scripts/setup_database.py` for new installations.

## 11. Troubleshooting

**PostgreSQL Connection Issues:**
- Verify PostgreSQL service is running
- Check `.env` database credentials
- Run `python backend/scripts/setup_database.py` to create the configured database.

**Migration Errors:**
- Run migrations in sequence from `backend/migrations/`
- Check for foreign key constraints
- Verify database user has CREATE permissions

**Test Failures:**
- Ensure database is populated with demo data
- Check backend is running on port 8000
- Verify `.env` configuration

**Frontend Build Errors:**
- Delete `node_modules` and reinstall: `rm -rf node_modules && npm install`
- Check Node.js version (18+)

**AI Assistant Not Working:**
- Verify Ollama is running: `ollama serve`
- Pull required models: `ollama pull qwen2.5:0.5b`
- Check `OLLAMA_BASE_URL` in `.env`

## 12. Project Structure

```
AI-TIP/
├── backend/              # FastAPI backend
│   ├── app/             # Application modules
│   │   ├── api/         # API endpoints
│   │   ├── auth/        # Authentication
│   │   ├── database/    # Database connection
│   │   ├── ai/          # AI/Graph RAG
│   │   ├── correlation/ # Threat correlation
│   │   ├── risk/        # Risk calculations
│   │   ├── threat_intel/ # Threat intelligence
│   │   └── notifications/ # Email notifications
│   ├── tests/           # Unit tests (161 tests)
│   ├── migrations/      # SQL migrations (38 files)
│   └── requirements.txt # Python dependencies
├── frontend/            # React frontend
│   ├── src/
│   │   ├── components/  # React components
│   │   ├── pages/       # Route pages
│   │   ├── api/         # API client
│   │   └── auth/        # Authentication context
│   └── package.json     # Node dependencies
├── database/            # Database files
│   ├── ai_tip_schema.sql  # Clean schema
│   └── ai_tip_dump.sql    # Demo data
├── docs/               # Documentation
└── README.md           # Project overview
```

## 13. Key Validation Results (Handoff)

- **Backend Tests:** 161/161 PASSED
- **Frontend Build:** PASS
- **MITRE Integrity:** 664 techniques, 6 assessment techniques, 0 orphan records
- **Vendor Relationships:** 110 vendors, 14 customer-vendor relationships, 0 missing vendor_id
- **Database:** Schema and demo dump verified
- **Security:** No hardcoded secrets in tracked files
- **API:** Backend starts successfully on port 8000

## 14. Contact

For questions about:
- **Architecture/Design:** Original developer
- **Database:** See `database/README.md`
- **API:** See http://localhost:8000/docs
- **Tests:** See `backend/tests/` directory
