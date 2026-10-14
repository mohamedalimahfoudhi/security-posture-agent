from fastapi import APIRouter, Depends, HTTPException
from app.auth.deps import get_current_user, require_roles
from app.threat_intel.schemas import ThreatArticleList, ThreatCollectionResult, ThreatProcessResult
from app.threat_intel.correlation.schemas import ThreatCorrelationList, ThreatCorrelationProcessResult
from app.threat_intel.service import ThreatIntelService
from app.threat_intel.scheduler import run_collection, is_collection_running

router = APIRouter(
    prefix="/api/threat-intel",
    tags=["ThreatIntel"]
)

service = ThreatIntelService()


@router.post("/collect", response_model=ThreatCollectionResult)
def collect_threat_intel(current_user: dict = Depends(require_roles("Admin", "Analyst"))):
    result = service.collect_hackernews()
    return result


@router.post("/collect/cve", response_model=ThreatCollectionResult)
def collect_cve_intel(current_user: dict = Depends(require_roles("Admin", "Analyst"))):
    result = service.collect_cve()
    return result


@router.post("/collect/bleepingcomputer", response_model=ThreatCollectionResult)
def collect_bleepingcomputer_intel(current_user: dict = Depends(require_roles("Admin", "Analyst"))):
    result = service.collect_bleepingcomputer()
    return result


@router.post("/collect/breaches")
def collect_data_breaches(current_user: dict = Depends(require_roles("Admin", "Analyst"))):
    """Trigger an immediate data-breach intelligence collection.

    Breach records are normalized into threat_events (source_type='breach_report')
    and are picked up by the existing third-party correlation + alert engine.
    """
    result = service.collect_data_breaches()
    return result


@router.post("/collect/all")
def collect_all_threat_intel(current_user: dict = Depends(require_roles("Admin", "Analyst"))):
    result = service.collect_all_sources()
    return result


# ----------------------------
# Data Breach Intelligence (tenant-scoped)
# ----------------------------

@router.get("/data-breaches")
def list_data_breaches(
    page: int = 1,
    limit: int = 20,
    current_user: dict = Depends(get_current_user)
):
    """List data breaches correlated to the current customer's third parties.

    Tenant-scoped: only breaches affecting the authenticated customer's
    vendors/third parties are returned. Never relies on frontend filtering.
    """
    customer_id = current_user["customer_id"]
    return service.list_data_breaches(customer_id=customer_id, page=page, limit=limit)


@router.get("/data-breaches/summary")
def get_data_breach_summary(current_user: dict = Depends(get_current_user)):
    """Return data-breach summary statistics for the current customer (tenant-scoped)."""
    customer_id = current_user["customer_id"]
    return service.get_data_breach_summary(customer_id=customer_id)


@router.get("/data-breaches/{breach_id}")
def get_data_breach(
    breach_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Return a single data breach with customer-specific context (tenant-scoped).

    Returns 404 if the breach is not correlated to the authenticated customer.
    """
    customer_id = current_user["customer_id"]
    breach = service.get_data_breach(customer_id=customer_id, breach_id=breach_id)
    if not breach:
        raise HTTPException(status_code=404, detail="Breach not found for this customer")
    return breach


@router.post("/refresh")
def refresh_threat_feed(current_user: dict = Depends(require_roles("Admin", "Analyst"))):
    """Trigger an immediate threat feed collection.

    Uses the scheduler's overlap protection so a collection already in
    progress is not started again. Returns the number of new articles,
    the completion timestamp and the last-updated value from the DB.
    """
    if is_collection_running():
        return {
            "status": "already_running",
            "message": "A threat feed collection is already in progress.",
            "inserted": 0,
            "duplicates": 0,
            "completed_at": None,
            "last_updated": service.get_last_updated(),
        }
    return run_collection(service)


@router.post("/process", response_model=ThreatProcessResult)
def process_threat_intel(current_user: dict = Depends(require_roles("Admin", "Analyst"))):
    result = service.process_unprocessed_articles(limit=20)
    return result


@router.post("/correlate", response_model=ThreatCorrelationProcessResult)
def correlate_threat_intel(
    limit: int = 20,
    force: bool = False,
    current_user: dict = Depends(require_roles("Admin", "Analyst"))
):
    customer_id = current_user["customer_id"]
    result = service.correlate_customer_articles(customer_id=customer_id, limit=limit, force=force)
    return result


@router.get("/correlations", response_model=ThreatCorrelationList)
def read_threat_correlations(
    page: int = 1,
    limit: int = 20,
    current_user: dict = Depends(get_current_user)
):
    customer_id = current_user["customer_id"]
    return service.list_correlations(customer_id=customer_id, page=page, limit=limit)


@router.get("/articles", response_model=ThreatArticleList)
def read_threat_articles(
    page: int = 1,
    limit: int = 20,
    current_user: dict = Depends(get_current_user)
):
    return service.list_articles(page=page, limit=limit)
