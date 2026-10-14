from fastapi import APIRouter, Depends, HTTPException
from app.auth.deps import get_current_user, require_roles
from app.database.connection import get_connection

router = APIRouter(
    prefix="/api/assets",
    tags=["Assets"]
)


@router.get("/")
async def get_assets(limit: int = 100, offset: int = 0, current_user: dict = Depends(get_current_user)):
    """Get all assets for a customer with pagination"""
    
    customer_id = current_user["customer_id"]
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT a.id, a.customer_id, a.document_id, a.technology, a.vendor, a.version,
               a.criticality, a.internet_exposed, a.sensitive_data, a.category,
               a.operating_system, a.database, a.cloud_provider, a.web_server,
               a.firewall, a.virtualization, a.programming_language, a.framework,
               a.security_tools, a.network_devices, a.confidence, a.created_at, a.updated_at,
               d.filename as source_document, a.vendor_id
        FROM assets a
        LEFT JOIN documents d ON a.document_id = d.id
        WHERE a.customer_id = %s
        ORDER BY a.created_at DESC
        LIMIT %s OFFSET %s
    """, (customer_id, limit, offset))
    
    assets = cur.fetchall()
    
    result = []
    for asset in assets:
        result.append({
            "id": asset[0],
            "customer_id": asset[1],
            "document_id": asset[2],
            "technology": asset[3],
            "vendor": asset[4],
            "version": asset[5],
            "criticality": asset[6],
            "internet_exposed": asset[7],
            "sensitive_data": asset[8],
            "category": asset[9],
            "operating_system": asset[10],
            "database": asset[11],
            "cloud_provider": asset[12],
            "web_server": asset[13],
            "firewall": asset[14],
            "virtualization": asset[15],
            "programming_language": asset[16],
            "framework": asset[17],
            "security_tools": asset[18],
            "network_devices": asset[19],
            "confidence": asset[20],
            "created_at": asset[21],
            "updated_at": asset[22],
            "source_document": asset[23],
            "vendor_id": asset[24]
        })
    
    # Get total count
    cur.execute("""
        SELECT COUNT(*)
        FROM assets a
        LEFT JOIN documents d ON a.document_id = d.id
        WHERE a.customer_id = %s
    """, (customer_id,))
    total = cur.fetchone()[0]
    
    cur.close()
    conn.close()
    
    return {
        "assets": result,
        "total": total,
        "limit": limit,
        "offset": offset
    }


@router.get("/customers/{customer_id}/assets")
async def get_customer_assets(
    customer_id: int,
    limit: int = 200,
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    """Get all assets for a specific customer (tenant-isolated, with vendor name and counts)."""
    # Tenant isolation: non-admin users can only see their own customer's assets
    if current_user.get("role") != "Admin" and customer_id != current_user["customer_id"]:
        raise HTTPException(status_code=403, detail="Cannot access other customers' assets")

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            a.id,
            a.customer_id,
            a.document_id,
            a.technology,
            a.vendor,
            a.version,
            a.criticality,
            a.internet_exposed,
            a.sensitive_data,
            a.category,
            a.confidence,
            a.created_at,
            a.updated_at,
            a.vendor_id,
            v.name AS vendor_name,
            -- Count active alerts linked to this asset's technology/vendor
            -- Note: alerts table has asset_vendor (TEXT) and asset_id columns, not vendor or asset_vendor_id
            (
                SELECT COUNT(*) FROM alerts al
                WHERE al.customer_id = a.customer_id
                  AND al.status NOT IN ('RESOLVED', 'DISMISSED')
                  AND (
                      al.asset_vendor ILIKE a.vendor
                      OR al.asset_id = a.id
                  )
            ) AS alerts_count,
            -- Exposure flag from internet_exposed column
            CASE WHEN a.internet_exposed THEN 1 ELSE 0 END AS exposures_count
        FROM assets a
        LEFT JOIN vendors v ON a.vendor_id = v.id
        WHERE a.customer_id = %s
        ORDER BY a.created_at DESC
        LIMIT %s OFFSET %s
    """, (customer_id, limit, offset))

    rows = cur.fetchall()

    result = []
    for row in rows:
        (
            asset_id, cust_id, doc_id, technology, vendor, version,
            criticality, internet_exposed, sensitive_data, category,
            confidence, created_at, updated_at,
            vendor_id, vendor_name, alerts_count, exposures_count
        ) = row

        result.append({
            "id": asset_id,
            "customer_id": cust_id,
            "document_id": doc_id,
            "technology": technology or "Unknown",
            "vendor": vendor_name or vendor or ("Customer / Internal" if vendor_id is None else "Unknown"),
            "version": version,
            "criticality": criticality,
            "internet_exposed": bool(internet_exposed),
            "sensitive_data": bool(sensitive_data),
            "category": category,
            "confidence": confidence,
            "created_at": created_at.isoformat() if created_at else None,
            "updated_at": updated_at.isoformat() if updated_at else None,
            "vendor_id": vendor_id,
            "alerts_count": int(alerts_count or 0),
            "exposures_count": int(exposures_count or 0),
            # risk_score: simple heuristic based on criticality + exposure + alerts
            "risk_score": (
                (90 if criticality == "CRITICAL" else 70 if criticality == "HIGH" else 50 if criticality == "MEDIUM" else 30)
                + (10 if internet_exposed else 0)
                + min(10, int(alerts_count or 0) * 2)
            ),
        })

    # Total count for pagination
    cur.execute("SELECT COUNT(*) FROM assets WHERE customer_id = %s", (customer_id,))
    total = cur.fetchone()[0]

    cur.close()
    conn.close()

    return {
        "assets": result,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/inventory")
async def get_asset_inventory(current_user: dict = Depends(get_current_user)):
    """Get technology inventory summary for a customer"""

    
    customer_id = current_user["customer_id"]
    conn = get_connection()
    cur = conn.cursor()
    
    # Get technology counts
    cur.execute("""
        SELECT technology, vendor, COUNT(*) as count, 
               MAX(version) as latest_version, 
               MAX(criticality) as max_criticality
        FROM assets a
        LEFT JOIN documents d ON a.document_id = d.id
        WHERE a.customer_id = %s
        GROUP BY technology, vendor
        ORDER BY count DESC
    """, (customer_id,))
    
    technologies = cur.fetchall()
    
    result = []
    for tech in technologies:
        result.append({
            "technology": tech[0],
            "vendor": tech[1],
            "count": tech[2],
            "latest_version": tech[3],
            "max_criticality": tech[4]
        })
    
    # Get category breakdown
    cur.execute("""
        SELECT category, COUNT(*) as count
        FROM assets a
        LEFT JOIN documents d ON a.document_id = d.id
        WHERE a.customer_id = %s AND a.category IS NOT NULL
        GROUP BY category
        ORDER BY count DESC
    """, (customer_id,))
    
    categories = cur.fetchall()
    category_breakdown = [
        {"category": cat[0], "count": cat[1]} for cat in categories
    ]
    
    # Get criticality breakdown
    cur.execute("""
        SELECT criticality, COUNT(*) as count
        FROM assets a
        LEFT JOIN documents d ON a.document_id = d.id
        WHERE a.customer_id = %s
        GROUP BY criticality
        ORDER BY count DESC
    """, (customer_id,))
    
    criticalities = cur.fetchall()
    criticality_breakdown = [
        {"criticality": crit[0], "count": crit[1]} for crit in criticalities
    ]
    
    cur.close()
    conn.close()
    
    return {
        "technologies": result,
        "category_breakdown": category_breakdown,
        "criticality_breakdown": criticality_breakdown,
        "total_technologies": len(result),
        "total_assets": sum(cat["count"] for cat in category_breakdown)
    }


@router.get("/detected-technologies")
async def get_detected_technologies(current_user: dict = Depends(get_current_user)):
    """Get detected technologies for dashboard widget"""
    
    customer_id = current_user["customer_id"]
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT DISTINCT technology, vendor, version, criticality
        FROM assets a
        LEFT JOIN documents d ON a.document_id = d.id
        WHERE a.customer_id = %s
        ORDER BY technology
    """, (customer_id,))
    
    technologies = cur.fetchall()
    
    result = []
    for tech in technologies:
        result.append({
            "technology": tech[0],
            "vendor": tech[1],
            "version": tech[2],
            "criticality": tech[3]
        })
    
    cur.close()
    conn.close()
    
    return {
        "technologies": result,
        "total_count": len(result)
    }


@router.get("/{asset_id}")
async def get_asset(asset_id: int, current_user: dict = Depends(get_current_user)):
    """Get a specific asset"""
    
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT a.id, a.customer_id, a.document_id, a.technology, a.vendor, a.version,
               a.criticality, a.internet_exposed, a.sensitive_data, a.category,
               a.operating_system, a.database, a.cloud_provider, a.web_server,
               a.firewall, a.virtualization, a.programming_language, a.framework,
               a.security_tools, a.network_devices, a.confidence, a.created_at, a.updated_at,
               a.extraction_metadata, d.filename as source_document, a.vendor_id
        FROM assets a
        LEFT JOIN documents d ON a.document_id = d.id
        WHERE a.id = %s AND a.customer_id = %s
    """, (asset_id, current_user["customer_id"]))
    
    asset = cur.fetchone()
    
    if not asset:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Asset not found")
    
    result = {
        "id": asset[0],
        "customer_id": asset[1],
        "document_id": asset[2],
        "technology": asset[3],
        "vendor": asset[4],
        "version": asset[5],
        "criticality": asset[6],
        "internet_exposed": asset[7],
        "sensitive_data": asset[8],
        "category": asset[9],
        "operating_system": asset[10],
        "database": asset[11],
        "cloud_provider": asset[12],
        "web_server": asset[13],
        "firewall": asset[14],
        "virtualization": asset[15],
        "programming_language": asset[16],
        "framework": asset[17],
        "security_tools": asset[18],
        "network_devices": asset[19],
        "confidence": asset[20],
        "created_at": asset[21],
        "updated_at": asset[22],
        "extraction_metadata": asset[23],
        "source_document": asset[24],
        "vendor_id": asset[25]
    }
    
    cur.close()
    conn.close()
    
    return result


@router.delete("/{asset_id}")
async def delete_asset(asset_id: int, current_user: dict = Depends(require_roles("Admin"))):
    """Delete an asset"""
    
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("DELETE FROM assets WHERE id = %s AND customer_id = %s", (asset_id, current_user["customer_id"]))
    
    if cur.rowcount == 0:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Asset not found")
    
    conn.commit()
    cur.close()
    conn.close()
    
    return {"message": "Asset deleted successfully"}
