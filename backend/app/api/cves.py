from fastapi import APIRouter, Depends
from app.auth.deps import get_current_user
from app.database.repository import get_cves

router = APIRouter(
    prefix="/api/cves",
    tags=["CVEs"]
)


@router.get("/")
def read_cves(current_user: dict = Depends(get_current_user)):
    cves = get_cves()

    return [
        {
            "id": cve[0],
            "cve_id": cve[1],
            "title": cve[2],
            "description": cve[3],
            "severity": cve[4],
            "cvss_score": cve[5],
            "published_at": cve[6],
            "source_url": cve[7]
        }
        for cve in cves
    ]
