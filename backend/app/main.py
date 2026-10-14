from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.ai.analyzer import analyze_cve
from app.threat_intel.scheduler import start_scheduler, shutdown_scheduler
from app.threat_intel.service import ThreatIntelService

from app.api import (
    cves,
    alerts,
    vendors,
    customers,
    assessments,
    dashboard,
    documents,
    assets,
    ai,
    applicability,
    notifications,
    reports
)
from app.api import architectures
from app.api import third_party_profiles
from app.api import customer_dashboard
from app.auth import router as auth
from app.auth.deps import require_roles
from app.threat_intel import router as threat_intel
from app.threat_intel.scheduler import run_collection


_service = ThreatIntelService()


@asynccontextmanager
async def lifespan(app):
    # Start the APScheduler (AsyncIOScheduler) on the async event loop.
    # The periodic collection job first fires after 30 minutes, so startup
    # remains fast and no collection runs immediately.
    start_scheduler(lambda: run_collection(_service))
    yield
    shutdown_scheduler()


app = FastAPI(
    title="AI-TIP",
    description="AI-powered Cyber Threat Intelligence Platform",
    version="1.0",
    lifespan=lifespan,
)


# ----------------------------
# CORS Configuration
# ----------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
        "http://localhost:5177",
        "http://127.0.0.1:5177",
        "http://localhost:5176",
        "http://127.0.0.1:5176",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------------
# API Routes
# ----------------------------

app.include_router(auth.router, prefix="/api")

app.include_router(cves.router)

app.include_router(alerts.router)

app.include_router(vendors.router)
app.include_router(architectures.router)
app.include_router(third_party_profiles.router)

app.include_router(customers.router)

app.include_router(assessments.router)

app.include_router(dashboard.router)

app.include_router(documents.router)

app.include_router(assets.router)

app.include_router(ai.router)

app.include_router(applicability.router)

app.include_router(notifications.router)

app.include_router(reports.router)

app.include_router(customer_dashboard.router)

app.include_router(threat_intel)

# ----------------------------
# Root Endpoint
# ----------------------------

@app.get("/")
def home():

    return {
        "project": "AI-TIP",
        "status": "backend running"
    }



# ----------------------------
# AI Analysis Endpoint
# ----------------------------

@app.post("/ai/analyze")
def analyze(data: dict, current_user: dict = Depends(require_roles("Admin", "Analyst"))):

    result = analyze_cve(data)

    return {
        "analysis": result
    }
