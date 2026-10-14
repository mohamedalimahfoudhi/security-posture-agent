# Third-Party Cybersecurity Posture Agent

Enterprise SOC dashboard for monitoring third-party cybersecurity risks affecting customers. Frontend-only with mock data.

## Backend (Python / FastAPI)

The backend is a FastAPI application located in this directory. It powers the
AI technology extraction, threat intelligence feed, and asset assessments.

### Prerequisites

- Python 3.11+ (tested with 3.14)
- A virtual environment in `backend/.venv`

### Setup

```bash
cd backend
python -m venv .venv          # create the virtual environment (first time only)
.venv\Scripts\activate        # activate on Windows
# or: source .venv/bin/activate   # on macOS / Linux

pip install -r requirements.txt   # install all dependencies (incl. apscheduler)
```

> **Note:** `apscheduler` is required for the automatic threat-intel refresh
> scheduler. If it is missing, the app still boots but the periodic refresh is
> disabled (a warning is logged). Install it with `pip install apscheduler`.

### Run the API server

```bash
.venv\Scripts\python -m uvicorn app.main:app --reload --port 8000
```

Open [http://localhost:8000/docs](http://localhost:8000/docs) for the interactive
API documentation.

---

## Frontend (React / Vite)

### Tech Stack

- React 19 + TypeScript
- Vite
- Tailwind CSS
- shadcn/ui components
- Lucide React icons
- Recharts
- TanStack Table
- React Router

### Getting Started

```bash
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

## Build

```bash
npm run build
npm run preview
```

## Pages

| Route | Description |
|-------|-------------|
| `/` | Dashboard with KPIs, charts, vendor risk cards, alerts table |
| `/alerts` | Full alerts listing with detail drawer |
| `/threat-feed` | Threat intelligence feed |
| `/third-parties` | Vendor risk posture grid |
| `/customers` | Customer monitoring table |
| `/ai-assistant` | ChatGPT-style AI assistant |
| `/reports` | Report generation cards |
| `/settings` | Platform configuration |

## Project Structure

```
src/
├── components/
│   ├── layout/       # Sidebar, Navbar, MainLayout
│   ├── shared/       # Reusable business components
│   └── ui/           # shadcn/ui primitives
├── data/             # Mock JSON data
├── lib/              # Utilities
├── pages/            # Route pages
└── types/            # TypeScript interfaces
```

## Notes

- No backend, authentication, or API calls
- All data is static mock data in `src/data/mock.ts`
- Dark theme optimized for SOC analyst workflows
