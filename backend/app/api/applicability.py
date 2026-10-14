from fastapi import APIRouter, Depends
from app.auth.deps import require_roles
from pydantic import BaseModel
from app.risk.vulnerability_applicability import assess_vulnerability_applicability
from app.database.assessment_repository import get_assets_for_customer

router = APIRouter(prefix="/api/applicability", tags=["Applicability"])


class ApplicabilityRequest(BaseModel):
    vulnerability_title: str
    assets: list[dict] | None = None


@router.post("/assess")
def assess_applicability(request: ApplicabilityRequest, current_user: dict = Depends(require_roles("Admin", "Analyst"))):
    customer_id = current_user["customer_id"]
    assets = request.assets
    if not assets:
        assets = get_assets_for_customer(customer_id)

    return assess_vulnerability_applicability(
        customer_id=customer_id,
        vulnerability_title=request.vulnerability_title,
        assets=assets,
    )
