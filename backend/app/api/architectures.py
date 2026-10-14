from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.auth.deps import get_current_user, require_roles
from app.database.connection import get_connection

router = APIRouter(prefix="/api/customers/{customer_id}", tags=["Third-Party Architectures"])

class ArchitectureInput(BaseModel):
    name: str
    description: Optional[str] = None
    criticality: str = "MEDIUM"
    business_purpose: Optional[str] = None
    risk_score: int = 0

def _tenant_customer(customer_id, current_user):
    if customer_id != current_user["customer_id"]:
        raise HTTPException(status_code=403, detail="Not authorized for this customer")

@router.get("/vendors/{vendor_id}/architectures")
def list_architectures(customer_id: int, vendor_id: int, current_user: dict = Depends(get_current_user)):
    _tenant_customer(customer_id, current_user)
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""SELECT a.id, a.name, a.description, a.criticality, a.business_purpose, a.risk_score,
        COUNT(DISTINCT t.id), COUNT(DISTINCT s.id), COUNT(DISTINCT e.id)
        FROM third_party_architectures a JOIN customer_vendors cv ON cv.id=a.customer_vendor_id
        LEFT JOIN architecture_technologies t ON t.architecture_id=a.id
        LEFT JOIN architecture_services s ON s.architecture_id=a.id
        LEFT JOIN third_party_exposures e ON e.architecture_id=a.id AND NOT e.acknowledged AND NOT e.muted
        WHERE cv.customer_id=%s AND cv.id=%s GROUP BY a.id ORDER BY a.risk_score DESC, a.name""", (customer_id, vendor_id))
    rows = cur.fetchall(); cur.close(); conn.close()
    return [{"id":r[0],"name":r[1],"description":r[2],"criticality":r[3],"business_purpose":r[4],"risk_score":r[5],"technology_count":r[6],"service_count":r[7],"alert_count":r[8]} for r in rows]

@router.post("/vendors/{vendor_id}/architectures")
def create_architecture(customer_id:int, vendor_id:int, data:ArchitectureInput, current_user:dict=Depends(require_roles("Admin"))):
    _tenant_customer(customer_id, current_user)
    conn=get_connection(); cur=conn.cursor()
    cur.execute("SELECT id FROM customer_vendors WHERE id=%s AND customer_id=%s",(vendor_id,customer_id))
    if not cur.fetchone(): cur.close(); conn.close(); raise HTTPException(404,"Vendor relationship not found")
    cur.execute("""INSERT INTO third_party_architectures(customer_vendor_id,name,description,criticality,business_purpose,risk_score)
        VALUES(%s,%s,%s,%s,%s,%s) RETURNING id""",(vendor_id,data.name,data.description,data.criticality,data.business_purpose,data.risk_score))
    architecture_id=cur.fetchone()[0]; conn.commit(); cur.close(); conn.close(); return {"id":architecture_id}

@router.put("/vendors/{vendor_id}/architectures/{architecture_id}")
def update_architecture(customer_id:int, vendor_id:int, architecture_id:int, data:ArchitectureInput, current_user:dict=Depends(require_roles("Admin"))):
    _tenant_customer(customer_id, current_user)
    conn=get_connection(); cur=conn.cursor()
    cur.execute("""UPDATE third_party_architectures a SET name=%s,description=%s,criticality=%s,business_purpose=%s,risk_score=%s,updated_at=CURRENT_TIMESTAMP
        FROM customer_vendors cv WHERE a.customer_vendor_id=cv.id AND a.id=%s AND cv.id=%s AND cv.customer_id=%s RETURNING a.id""",(data.name,data.description,data.criticality,data.business_purpose,data.risk_score,architecture_id,vendor_id,customer_id))
    if not cur.fetchone(): conn.rollback(); cur.close(); conn.close(); raise HTTPException(404,"Architecture not found")
    conn.commit(); cur.close(); conn.close(); return {"id":architecture_id}

@router.delete("/vendors/{vendor_id}/architectures/{architecture_id}")
def delete_architecture(customer_id:int, vendor_id:int, architecture_id:int, current_user:dict=Depends(require_roles("Admin"))):
    _tenant_customer(customer_id, current_user)
    conn=get_connection(); cur=conn.cursor()
    cur.execute("""DELETE FROM third_party_architectures a USING customer_vendors cv
        WHERE a.customer_vendor_id=cv.id AND a.id=%s AND cv.id=%s AND cv.customer_id=%s""",(architecture_id,vendor_id,customer_id))
    if not cur.rowcount: conn.rollback(); cur.close(); conn.close(); raise HTTPException(404,"Architecture not found")
    conn.commit(); cur.close(); conn.close(); return {"message":"Architecture deleted"}

@router.get("/architectures/{architecture_id}")
def architecture_detail(customer_id:int, architecture_id:int, current_user:dict=Depends(get_current_user)):
    _tenant_customer(customer_id, current_user)
    conn=get_connection(); cur=conn.cursor()
    cur.execute("""SELECT a.id,a.name,a.description,a.criticality,a.business_purpose,a.risk_score,cv.vendor
        FROM third_party_architectures a JOIN customer_vendors cv ON cv.id=a.customer_vendor_id
        WHERE a.id=%s AND cv.customer_id=%s""",(architecture_id,customer_id)); row=cur.fetchone()
    if not row: cur.close(); conn.close(); raise HTTPException(404,"Architecture not found")
    cur.execute("SELECT technology_name,version,role,asset_id FROM architecture_technologies WHERE architecture_id=%s",(architecture_id,)); technologies=cur.fetchall()
    cur.execute("SELECT service_name,description,criticality FROM architecture_services WHERE architecture_id=%s",(architecture_id,)); services=cur.fetchall()
    cur.execute("""SELECT te.title,te.cve_id,e.risk_score,e.priority FROM third_party_exposures e JOIN threat_events te ON te.id=e.threat_event_id
        WHERE e.architecture_id=%s ORDER BY e.risk_score DESC""",(architecture_id,)); threats=cur.fetchall()
    cur.close(); conn.close()
    return {"id":row[0],"name":row[1],"description":row[2],"criticality":row[3],"business_purpose":row[4],"risk_score":row[5],"vendor":row[6],"technologies":[{"name":x[0],"version":x[1],"role":x[2],"asset_id":x[3]} for x in technologies],"services":[{"name":x[0],"description":x[1],"criticality":x[2]} for x in services],"threats":[{"title":x[0],"cve_id":x[1],"risk_score":x[2],"priority":x[3]} for x in threats]}
