from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from app.auth.deps import get_current_user, require_roles
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from app.database.repository import get_customer_vendors
from app.database.connection import get_connection
from app.services.vendor_resolution import VendorResolutionService
from app.services.csv_import import CSVImportService
from app.services.architecture_preview import ArchitecturePreviewService
from app.ai.vendor_ecosystem_extractor import VendorEcosystemExtractor

router = APIRouter(
    prefix="/api/vendors",
    tags=["Vendors"]
)

# Pydantic models for customer vendor relationships
class CustomerVendorCreate(BaseModel):
    vendor: str
    relationship_type: str
    data_sensitivity: str
    technology: Optional[str] = None
    criticality: Optional[str] = None
    confidence: Optional[int] = 100
    notes: Optional[str] = None
    # Third-party profile fields (optional)
    business_role: Optional[str] = None
    data_access_level: Optional[str] = None
    privileged_access: Optional[bool] = False
    architecture_document_id: Optional[int] = None
    sla_penalty_risk: Optional[int] = None
    regulatory_flags: Optional[list] = None
    auto_create_vendor: Optional[bool] = False  # Whether to auto-create vendor if not found

class CustomerVendorUpdate(BaseModel):
    vendor: Optional[str] = None
    relationship_type: Optional[str] = None
    data_sensitivity: Optional[str] = None
    technology: Optional[str] = None
    criticality: Optional[str] = None
    confidence: Optional[int] = None
    notes: Optional[str] = None


class CSVImportConfirm(BaseModel):
    valid_rows: list
    auto_create_vendor: bool = False


class ArchitectureImportPreview(BaseModel):
    document_id: int
    customer_vendor_id: int


class ArchitectureImportConfirm(BaseModel):
    document_id: int
    customer_vendor_id: int
    approved_technologies: list
    approved_services: list


class EcosystemImportPreview(BaseModel):
    document_id: int
    customer_id: Optional[int] = None  # For Admin to specify customer


class EcosystemImportConfirm(BaseModel):
    document_id: int
    customer_id: Optional[int] = None
    accepted_vendors: List[Any] = []
    rejected_vendors: List[Any] = []
    edited_vendors: Optional[List[Dict[str, Any]]] = None
    accepted_customer_technologies: List[Any] = []
    rejected_customer_technologies: List[Any] = []
    edited_customer_technologies: Optional[List[Dict[str, Any]]] = None


@router.get("/")
def read_vendors(current_user: dict = Depends(get_current_user)):
    customer_id = current_user["customer_id"]
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
            SELECT id, customer_id, vendor, technology, criticality,
                   relationship_type, data_sensitivity, source_document_id,
                   confidence, notes, created_at
            FROM customer_vendors
            WHERE customer_id = %s
            ORDER BY created_at DESC
    """, (customer_id,))

    vendors = cur.fetchall()
    cur.close()
    conn.close()

    return [
        {
            "id": vendor[0],
            "customer_id": vendor[1],
            "vendor": vendor[2],
            "technology": vendor[3],
            "criticality": vendor[4],
            "relationship_type": vendor[5],
            "data_sensitivity": vendor[6],
            "source_document_id": vendor[7],
            "confidence": vendor[8],
            "notes": vendor[9],
            "created_at": vendor[10].isoformat() if vendor[10] else None
        }
        for vendor in vendors
    ]


@router.post("/")
def create_vendor(vendor: CustomerVendorCreate, current_user: dict = Depends(require_roles("Admin"))):
    conn = get_connection()
    cur = conn.cursor()
    profile_id = None
    architecture_result = None

    try:
        # 1. Resolve vendor name to canonical vendor ID
        vendor_id, canonical_name, was_created, confidence = VendorResolutionService.get_or_create_vendor(
            vendor.vendor,
            auto_create=vendor.auto_create_vendor
        )
        
        if not vendor_id:
            raise HTTPException(
                status_code=400,
                detail=f"Vendor '{vendor.vendor}' not found. Set auto_create_vendor=true to create it automatically."
            )

        # 2. Check if customer-vendor relationship already exists
        cur.execute("""
            SELECT id FROM customer_vendors
            WHERE customer_id = %s AND vendor_id = %s
        """, (current_user["customer_id"], vendor_id))
        
        existing_cv = cur.fetchone()
        if existing_cv:
            raise HTTPException(
                status_code=409,
                detail=f"Customer-vendor relationship for '{canonical_name}' already exists."
            )

        # 3. Insert the customer-vendor relationship with vendor_id
        cur.execute("""
            INSERT INTO customer_vendors
            (customer_id, vendor_id, vendor, technology, criticality,
             relationship_type, data_sensitivity, source_document_id,
             confidence, notes, sla_penalty_risk, regulatory_flags, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
        """, (
            current_user["customer_id"],
            vendor_id,
            canonical_name,  # Use canonical name
            vendor.technology,
            vendor.criticality or "MEDIUM",
            vendor.relationship_type,
            vendor.data_sensitivity or "MEDIUM",
            vendor.architecture_document_id,
            vendor.confidence,
            vendor.notes,
            vendor.sla_penalty_risk,
            vendor.regulatory_flags
        ))

        customer_vendor_id = cur.fetchone()[0]

        # 4. Create a third-party profile with business context
        cur.execute("""
            INSERT INTO third_party_profiles
                (customer_vendor_id, business_role, data_access_level,
                 privileged_access, criticality, document_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (customer_vendor_id) DO UPDATE SET
                business_role = EXCLUDED.business_role,
                data_access_level = EXCLUDED.data_access_level,
                privileged_access = EXCLUDED.privileged_access,
                criticality = EXCLUDED.criticality,
                document_id = EXCLUDED.document_id
            RETURNING id
        """, (
            customer_vendor_id,
            vendor.business_role,
            vendor.data_access_level or vendor.data_sensitivity,
            vendor.privileged_access,
            vendor.criticality or "MEDIUM",
            vendor.architecture_document_id
        ))
        profile_id = cur.fetchone()[0]

        conn.commit()

        # 5. If an architecture document was provided, extract technologies/services
        if vendor.architecture_document_id:
            try:
                from app.risk.vendor_architecture_processor import process_vendor_architecture
                architecture_result = process_vendor_architecture(
                    customer_vendor_id=customer_vendor_id,
                    document_id=vendor.architecture_document_id,
                    customer_id=current_user["customer_id"],
                )
            except Exception as arch_error:
                # Document may be newly uploaded but extraction failed;
                # the relationship still succeeds but returns a warning.
                architecture_result = {
                    "error": str(arch_error),
                    "technologies_added": 0,
                    "services_added": 0,
                }

        cur.close()
        conn.close()

        return {
            "id": customer_vendor_id,
            "vendor_id": vendor_id,
            "canonical_vendor": canonical_name,
            "profile_id": profile_id,
            "message": "Vendor relationship created successfully",
            "architecture_processing": architecture_result,
            "vendor_created": was_created,
            "resolution_confidence": confidence,
        }
    except HTTPException:
        conn.rollback()
        cur.close()
        conn.close()
        raise
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{vendor_id}")
def update_vendor(vendor_id: int, vendor: CustomerVendorUpdate, current_user: dict = Depends(require_roles("Admin"))):
    conn = get_connection()
    cur = conn.cursor()

    # Build update query dynamically based on provided fields
    update_fields = []
    values = []

    if vendor.vendor is not None:
        update_fields.append("vendor = %s")
        values.append(vendor.vendor)
    if vendor.relationship_type is not None:
        update_fields.append("relationship_type = %s")
        values.append(vendor.relationship_type)
    if vendor.data_sensitivity is not None:
        update_fields.append("data_sensitivity = %s")
        values.append(vendor.data_sensitivity)
    if vendor.technology is not None:
        update_fields.append("technology = %s")
        values.append(vendor.technology)
    if vendor.criticality is not None:
        update_fields.append("criticality = %s")
        values.append(vendor.criticality)
    if vendor.confidence is not None:
        update_fields.append("confidence = %s")
        values.append(vendor.confidence)
    if vendor.notes is not None:
        update_fields.append("notes = %s")
        values.append(vendor.notes)

    if not update_fields:
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="No fields to update")

    values.extend([vendor_id, current_user["customer_id"]])

    try:
        cur.execute(f"""
            UPDATE customer_vendors
            SET {', '.join(update_fields)}
            WHERE id = %s AND customer_id = %s
        """, values)

        if cur.rowcount == 0:
            cur.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Vendor relationship not found")

        conn.commit()
        cur.close()
        conn.close()

        return {"message": "Vendor relationship updated successfully"}
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{vendor_id}")
def delete_vendor(vendor_id: int, current_user: dict = Depends(require_roles("Admin"))):
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            DELETE FROM customer_vendors
            WHERE id = %s AND customer_id = %s
        """, (vendor_id, current_user["customer_id"]))

        if cur.rowcount == 0:
            cur.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Vendor relationship not found")

        conn.commit()
        cur.close()
        conn.close()

        return {"message": "Vendor relationship deleted successfully"}
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/import/csv")
async def import_csv_preview(
    file: UploadFile = File(...),
    auto_create_vendor: bool = False,
    current_user: dict = Depends(require_roles("Admin"))
):
    """
    Upload and preview CSV import without committing.
    """
    # Read file content
    content = await file.read()
    
    # Decode if bytes
    if isinstance(content, bytes):
        content = content.decode('utf-8')
    
    # Parse CSV
    try:
        rows = CSVImportService.parse_csv(content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"CSV parsing error: {str(e)}")
    
    # Preview import
    preview = CSVImportService.preview_import(
        rows,
        current_user["customer_id"],
        auto_create_vendor=auto_create_vendor
    )
    
    return preview


@router.post("/import/csv/confirm")
def import_csv_confirm(
    confirmation: CSVImportConfirm,
    current_user: dict = Depends(require_roles("Admin"))
):
    """
    Confirm and commit the CSV import.
    """
    # Commit the valid rows
    result = CSVImportService.commit_import(
        confirmation.valid_rows,
        current_user["customer_id"]
    )
    
    if not result['success']:
        raise HTTPException(status_code=500, detail=result.get('error', 'Import failed'))
    
    return result


@router.post("/import/architecture/preview")
def import_architecture_preview(
    preview: ArchitectureImportPreview,
    current_user: dict = Depends(require_roles("Admin"))
):
    """
    Preview architecture document extraction without committing.
    """
    # Verify customer_vendor_id belongs to the user's customer
    conn = get_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT id FROM customer_vendors
            WHERE id = %s AND customer_id = %s
        """, (preview.customer_vendor_id, current_user["customer_id"]))
        
        if not cur.fetchone():
            raise HTTPException(
                status_code=404,
                detail="Customer-vendor relationship not found"
            )
        
        # Get preview of extraction
        extraction_preview = ArchitecturePreviewService.preview_extraction(
            preview.document_id,
            current_user["customer_id"]
        )
        
        # Get current profile state for comparison
        current_state = ArchitecturePreviewService.get_current_profile_state(
            preview.customer_vendor_id
        )
        
        return {
            "extraction_preview": extraction_preview,
            "current_state": current_state,
        }
        
    finally:
        cur.close()
        conn.close()


@router.post("/import/architecture/confirm")
def import_architecture_confirm(
    confirmation: ArchitectureImportConfirm,
    current_user: dict = Depends(require_roles("Admin"))
):
    """
    Confirm and commit the architecture extraction.
    """
    # Verify customer_vendor_id belongs to the user's customer
    conn = get_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT id FROM customer_vendors
            WHERE id = %s AND customer_id = %s
        """, (confirmation.customer_vendor_id, current_user["customer_id"]))
        
        if not cur.fetchone():
            raise HTTPException(
                status_code=404,
                detail="Customer-vendor relationship not found"
            )
        
        # Process the architecture using the existing processor
        from app.risk.vendor_architecture_processor import process_vendor_architecture
        
        result = process_vendor_architecture(
            customer_vendor_id=confirmation.customer_vendor_id,
            document_id=confirmation.document_id,
            customer_id=current_user["customer_id"]
        )
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()


@router.get("/customers/{customer_id}/ecosystem-summary")
def get_customer_ecosystem_summary(customer_id: int, current_user: dict = Depends(get_current_user)):
    """
    Get aggregated metrics for customer's third-party ecosystem.
    """
    # Verify customer access
    if current_user.get("role") != "Admin" and customer_id != current_user["customer_id"]:
        raise HTTPException(status_code=403, detail="Cannot access other customers' data")
    
    conn = get_connection()
    cur = conn.cursor()
    
    try:
        # Total vendors
        cur.execute("""
            SELECT COUNT(*) FROM customer_vendors WHERE customer_id = %s
        """, (customer_id,))
        total_vendors = cur.fetchone()[0]
        
        # Critical vendors
        cur.execute("""
            SELECT COUNT(*) FROM customer_vendors 
            WHERE customer_id = %s AND UPPER(criticality) = 'CRITICAL'
        """, (customer_id,))
        critical_vendors = cur.fetchone()[0]
        
        # High risk vendors (risk_score >= 70)
        cur.execute("""
            SELECT COUNT(*) FROM customer_vendors 
            WHERE customer_id = %s AND base_risk_score >= 70
        """, (customer_id,))
        high_risk_vendors = cur.fetchone()[0]
        
        # Active exposures
        cur.execute("""
            SELECT COUNT(*) FROM third_party_exposures 
            WHERE customer_id = %s AND acknowledged = FALSE
        """, (customer_id,))
        active_exposures = cur.fetchone()[0]
        
        # Critical alerts
        cur.execute("""
            SELECT COUNT(*) FROM third_party_alerts 
            WHERE customer_id = %s AND severity = 'CRITICAL' AND status = 'NEW'
        """, (customer_id,))
        critical_alerts = cur.fetchone()[0]
        
        return {
            "total_vendors": total_vendors,
            "critical_vendors": critical_vendors,
            "high_risk_vendors": high_risk_vendors,
            "active_exposures": active_exposures,
            "critical_alerts": critical_alerts
        }
        
    finally:
        cur.close()
        conn.close()


@router.get("/customers/{customer_id}/vendors/{vendor_id}/profile")
def get_vendor_profile(customer_id: int, vendor_id: int, current_user: dict = Depends(get_current_user)):
    """
    Get comprehensive vendor profile including technologies, services, exposures, and alerts.
    """
    # Verify customer access
    if current_user.get("role") != "Admin" and customer_id != current_user["customer_id"]:
        raise HTTPException(status_code=403, detail="Cannot access other customers' data")
    
    conn = get_connection()
    cur = conn.cursor()
    
    try:
        # Get customer vendor relationship
        cur.execute("""
            SELECT cv.id, cv.vendor, cv.relationship_type, cv.criticality, cv.data_sensitivity,
                   cv.notes, cv.source_document_id, cv.confidence
            FROM customer_vendors cv
            WHERE cv.customer_id = %s AND cv.vendor_id = %s
        """, (customer_id, vendor_id))
        
        cv_data = cur.fetchone()
        if not cv_data:
            raise HTTPException(status_code=404, detail="Customer vendor relationship not found")
        
        # Get third-party profile
        cur.execute("""
            SELECT id, business_role, data_access_level, privileged_access, criticality, risk_score
            FROM third_party_profiles
            WHERE customer_vendor_id = %s
        """, (cv_data[0],))
        
        profile_data = cur.fetchone()
        
        # Get technologies
        cur.execute("""
            SELECT technology, version, category, source
            FROM third_party_profile_technologies
            WHERE profile_id = %s
            ORDER BY created_at DESC
        """, (profile_data[0] if profile_data else None,))
        
        technologies = []
        for row in cur.fetchall():
            technologies.append({
                "technology": row[0],
                "version": row[1],
                "category": row[2],
                "source": row[3]
            })
        
        # Get services
        cur.execute("""
            SELECT service_name, category, criticality
            FROM third_party_profile_services
            WHERE profile_id = %s
            ORDER BY created_at DESC
        """, (profile_data[0] if profile_data else None,))
        
        services = []
        for row in cur.fetchall():
            services.append({
                "service_name": row[0],
                "category": row[1],
                "criticality": row[2]
            })
        
        # Get exposures
        cur.execute("""
            SELECT e.id, e.threat_event_id, te.cve_id, e.matched_text, e.risk_score, 
                   e.match_type, e.match_confidence, te.title, e.acknowledged, e.created_at
            FROM third_party_exposures e
            LEFT JOIN threat_events te ON te.id = e.threat_event_id
            WHERE e.customer_id = %s AND e.vendor_id = %s
            ORDER BY e.risk_score DESC, e.created_at DESC
            LIMIT 20
        """, (customer_id, vendor_id))
        
        exposures = []
        for row in cur.fetchall():
            exposures.append({
                "id": row[0],
                "threat_event_id": row[1],
                "cve_id": row[2],
                "affected_technology": row[3],
                "risk_score": row[4],
                "match_type": row[5],
                "match_confidence": row[6],
                "title": row[7],
                "acknowledged": row[8],
                "created_at": row[9]
            })
        
        # Get alerts
        cur.execute("""
            SELECT id, cve_id, threat_event_id, alert_type, severity, risk_score, 
                   status, created_at, recommended_action
            FROM third_party_alerts
            WHERE customer_id = %s AND customer_vendor_id = %s
            ORDER BY created_at DESC
            LIMIT 20
        """, (customer_id, cv_data[0]))
        
        alerts = []
        for row in cur.fetchall():
            alerts.append({
                "id": row[0],
                "cve_id": row[1],
                "threat_event_id": row[2],
                "alert_type": row[3],
                "severity": row[4],
                "risk_score": row[5],
                "status": row[6],
                "created_at": row[7],
                "recommended_action": row[8]
            })
        
        return {
            "customer_vendor": {
                "id": cv_data[0],
                "vendor": cv_data[1],
                "relationship_type": cv_data[2],
                "criticality": cv_data[3],
                "data_sensitivity": cv_data[4],
                "notes": cv_data[5],
                "source_document_id": cv_data[6],
                "confidence": cv_data[7]
            },
            "profile": {
                "id": profile_data[0] if profile_data else None,
                "business_role": profile_data[1] if profile_data else None,
                "data_access_level": profile_data[2] if profile_data else None,
                "privileged_access": profile_data[3] if profile_data else None,
                "criticality": profile_data[4] if profile_data else None,
                "risk_score": profile_data[5] if profile_data else None
            },
            "technologies": technologies,
            "services": services,
            "exposures": exposures,
            "alerts": alerts
        }
        
    finally:
        cur.close()
        conn.close()


@router.get("/customers/{customer_id}/alerts")
def get_customer_alerts(customer_id: int, current_user: dict = Depends(get_current_user)):
    """
    Get customer-specific alerts with vendor and CVE details.
    """
    # Verify customer access
    if current_user.get("role") != "Admin" and customer_id != current_user["customer_id"]:
        raise HTTPException(status_code=403, detail="Cannot access other customers' data")
    
    conn = get_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT ta.id, ta.customer_id, ta.customer_vendor_id, ta.cve_id, ta.threat_event_id,
                   ta.alert_type, ta.severity, ta.risk_score, ta.status, ta.created_at,
                   cv.vendor, cv.relationship_type,
                   ta.affected_technology, te.affected_products, te.title
            FROM third_party_alerts ta
            JOIN customer_vendors cv ON cv.id = ta.customer_vendor_id
            LEFT JOIN threat_events te ON te.id = ta.threat_event_id
            WHERE ta.customer_id = %s
            ORDER BY ta.created_at DESC
            LIMIT 100
        """, (customer_id,))
        
        alerts = []
        for row in cur.fetchall():
            alerts.append({
                "id": row[0],
                "customer_id": row[1],
                "customer_vendor_id": row[2],
                "cve_id": row[3],
                "threat_event_id": row[4],
                "alert_type": row[5],
                "severity": row[6],
                "risk_score": row[7],
                "status": row[8],
                "created_at": row[9],
                "vendor": row[10],
                "relationship_type": row[11],
                "affected_technology": row[12],
                "affected_products": row[13],
                "title": row[14]
            })
        
        return alerts
        
    finally:
        cur.close()
        conn.close()


@router.post("/import/ecosystem/preview")
def import_ecosystem_preview(
    preview: EcosystemImportPreview,
    current_user: dict = Depends(require_roles("Admin"))
):
    """
    Preview vendor ecosystem extraction from a document without committing.
    Uses AI to extract vendors, technologies, and relationships.
    """
    # Determine customer_id (Admin can specify, otherwise use own)
    customer_id = preview.customer_id if preview.customer_id else current_user["customer_id"]
    
    # Verify customer access (Admin can access any customer)
    if current_user.get("role") != "Admin" and customer_id != current_user["customer_id"]:
        raise HTTPException(
            status_code=403,
            detail="Cannot access other customers' data"
        )
    
    conn = get_connection()
    cur = conn.cursor()
    
    try:
        # Verify document exists and belongs to customer
        cur.execute("""
            SELECT id, filename, file_type, file_path
            FROM documents
            WHERE id = %s AND customer_id = %s
        """, (preview.document_id, customer_id))
        
        document = cur.fetchone()
        if not document:
            raise HTTPException(
                status_code=404,
                detail="Document not found"
            )
        
        doc_id, filename, file_type, file_path = document
        
        # Extract text content based on file type
        from app.document_processor import DocumentProcessor
        processor = DocumentProcessor()
        
        try:
            with open(file_path, "rb") as f:
                content = f.read()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to read file: {str(e)}")
            
        if file_type == "pdf":
            text_content = processor.extract_text_from_pdf(content)
        elif file_type in ["docx", "doc"]:
            text_content = processor.extract_text_from_docx(content)
        elif file_type in ["xlsx", "xls", "csv"]:
            text_content = processor.extract_text_from_excel(content)
        else:
            text_content = content.decode("utf-8", errors="ignore") if isinstance(content, bytes) else str(content)

        # Run vendor ecosystem extraction
        extractor = VendorEcosystemExtractor()
        extraction_result = extractor.extract_from_text(text_content, filename)
        
        if extraction_result.get("status") == "failed":
            raise HTTPException(
                status_code=500,
                detail=f"Extraction failed: {extraction_result.get('reason')}"
            )
        
        # Get existing customer vendors for comparison
        cur.execute("""
            SELECT id, vendor, relationship_type, criticality, data_sensitivity
            FROM customer_vendors
            WHERE customer_id = %s
        """, (customer_id,))
        
        existing_vendors = []
        for row in cur.fetchall():
            existing_vendors.append({
                "id": row[0],
                "vendor": row[1],
                "relationship_type": row[2],
                "criticality": row[3],
                "data_sensitivity": row[4],
            })
        
        return {
            "document_id": doc_id,
            "document_name": filename,
            "file_type": file_type,
            "customer_id": customer_id,
            "vendors": extraction_result.get("vendors", []),
            "customer_technologies": extraction_result.get("customer_technologies", []),
            "existing_vendors": existing_vendors,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()


@router.post("/import/ecosystem/confirm")
def import_ecosystem_confirm(
    confirmation: EcosystemImportConfirm,
    current_user: dict = Depends(require_roles("Admin"))
):
    """
    Confirm and commit the vendor ecosystem extraction.
    Creates customer-vendor relationships for accepted entities.
    """
    # Determine customer_id (Admin can specify, otherwise use own)
    customer_id = confirmation.customer_id if confirmation.customer_id else current_user["customer_id"]
    
    # Verify customer access
    if current_user.get("role") != "Admin" and customer_id != current_user["customer_id"]:
        raise HTTPException(
            status_code=403,
            detail="Cannot access other customers' data"
        )
    
    conn = get_connection()
    cur = conn.cursor()
    
    try:
        # Verify document exists and belongs to customer
        cur.execute("""
            SELECT id, filename, file_type, file_path
            FROM documents
            WHERE id = %s AND customer_id = %s
        """, (confirmation.document_id, customer_id))
        
        document = cur.fetchone()
        if not document:
            raise HTTPException(
                status_code=404,
                detail="Document not found"
            )
        
        doc_id, filename, file_type, file_path = document
        
        # Extract text content
        from app.document_processor import DocumentProcessor
        processor = DocumentProcessor()
        
        try:
            with open(file_path, "rb") as f:
                content = f.read()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to read file: {str(e)}")
        
        if file_type == "pdf":
            text_content = processor.extract_text_from_pdf(content)
        elif file_type in ["docx", "doc"]:
            text_content = processor.extract_text_from_docx(content)
        elif file_type in ["xlsx", "xls", "csv"]:
            text_content = processor.extract_text_from_excel(content)
        else:
            text_content = content.decode("utf-8", errors="ignore") if isinstance(content, bytes) else str(content)
        
        # Run extraction to get entities
        extractor = VendorEcosystemExtractor()
        extraction_result = extractor.extract_from_text(text_content, filename)
        
        if extraction_result.get("status") == "failed":
            raise HTTPException(
                status_code=500,
                detail=f"Extraction failed: {extraction_result.get('reason')}"
            )
        
        vendors = extraction_result.get("vendors", [])
        customer_technologies = extraction_result.get("customer_technologies", [])
        
        # Helper to normalize accepted items: frontend may send objects or indices
        def _resolve_index(item, fallback_list):
            if isinstance(item, dict):
                # Object form: { index: N, ... } or { name: "..." }
                if "index" in item:
                    return item["index"]
                # Match by name
                name = item.get("name") or item.get("vendor") or item.get("technology")
                for i, ent in enumerate(fallback_list):
                    ent_name = ent.get("name") or ent.get("vendor") or ent.get("technology")
                    if ent_name and name and str(ent_name).lower() == str(name).lower():
                        return i
                return None
            if isinstance(item, int):
                return item
            return None
        
        # Process accepted vendors
        created_vendors = []
        updated_vendors = []
        skipped_vendors = []
        
        for item in confirmation.accepted_vendors:
            idx = _resolve_index(item, vendors)
            if idx is None or idx >= len(vendors):
                skipped_vendors.append({"index": idx, "reason": "Index out of range"})
                continue
            
            entity = vendors[idx]
            
            # If the item is a dict, use its fields directly (frontend sends full objects)
            if isinstance(item, dict):
                entity = {**entity, **{k: v for k, v in item.items() if k != "index" and v is not None}}
            
            # Check if edited version provided
            edited = None
            if confirmation.edited_vendors:
                for edited_entity in confirmation.edited_vendors:
                    if edited_entity.get("index") == idx:
                        edited = edited_entity
                        break
            
            # Use edited values if provided, otherwise use extracted values
            name = edited.get("name") if edited else entity.get("name")
            relationship_type = edited.get("relationship_type") if edited else entity.get("relationship_type")
            criticality = edited.get("criticality") if edited else entity.get("criticality")
            data_sensitivity = edited.get("data_sensitivity") if edited else entity.get("data_sensitivity")
            evidence = edited.get("evidence") if edited else entity.get("evidence")
            risk_factors = edited.get("risk_factors") if edited else entity.get("risk_factors")
            technologies = edited.get("technologies") if edited else entity.get("technologies")
            
            # Normalize technologies: could be list of strings or list of dicts
            if technologies:
                tech_names = []
                for t in technologies:
                    if isinstance(t, dict):
                        tech_names.append(t.get("technology") or t.get("name"))
                    else:
                        tech_names.append(t)
                technologies = [t for t in tech_names if t]
            else:
                technologies = []
            
            # Skip empty names
            if not name:
                skipped_vendors.append({"index": idx, "reason": "Empty vendor name"})
                continue
            
            # Resolve vendor (get_or_create since auto_create is desired)
            vendor_id, canonical_name, was_created, resolution_confidence = VendorResolutionService.get_or_create_vendor(
                name,
                auto_create=True
            )
            
            if not vendor_id:
                skipped_vendors.append({"index": idx, "reason": "Vendor resolution failed"})
                continue
            
            name = canonical_name or name
            
            # Check if customer-vendor relationship already exists
            cur.execute("""
                SELECT id, criticality, data_sensitivity, relationship_type
                FROM customer_vendors
                WHERE customer_id = %s AND vendor_id = %s
            """, (customer_id, vendor_id))
            
            existing = cur.fetchone()
            
            if existing:
                # Update existing relationship
                cv_id = existing[0]
                cur.execute("""
                    UPDATE customer_vendors
                    SET relationship_type = %s,
                        criticality = %s,
                        data_sensitivity = %s,
                        notes = COALESCE(notes, '') || %s,
                        source_document_id = %s,
                        updated_at = NOW()
                    WHERE id = %s
                """, (
                    relationship_type,
                    criticality,
                    data_sensitivity,
                    f"\nUpdated from {filename}: {evidence}",
                    doc_id,
                    cv_id
                ))
                
                updated_vendors.append({
                    "customer_vendor_id": cv_id,
                    "vendor_id": vendor_id,
                    "name": name,
                    "action": "updated"
                })
            else:
                # Create new customer-vendor relationship
                cur.execute("""
                    INSERT INTO customer_vendors
                    (customer_id, vendor_id, vendor, relationship_type, criticality,
                     data_sensitivity, source_document_id, notes, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                    RETURNING id
                """, (
                    customer_id,
                    vendor_id,
                    name,
                    relationship_type,
                    criticality,
                    data_sensitivity,
                    doc_id,
                    f"Imported from {filename}: {evidence}"
                ))
                
                cv_id = cur.fetchone()[0]
                
                # Create third-party profile
                risk_factors = risk_factors or {}
                privileged_access = risk_factors.get("privileged_access", False)
                business_dependency = risk_factors.get("business_dependency", "MEDIUM")
                
                cur.execute("""
                    INSERT INTO third_party_profiles
                    (customer_vendor_id, business_role, data_access_level, privileged_access,
                     criticality, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
                    RETURNING id
                """, (
                    cv_id,
                    relationship_type,
                    data_sensitivity,
                    privileged_access,
                    criticality
                ))
                
                profile_id = cur.fetchone()[0]
                
                # Add technologies to profile
                for tech in technologies:
                    cur.execute("""
                        INSERT INTO third_party_profile_technologies
                        (profile_id, technology, category, created_at)
                        VALUES (%s, %s, %s, NOW())
                    """, (profile_id, tech, "other"))
                    
                    # Also add to assets table for Technology Inventory
                    cur.execute("""
                        INSERT INTO assets
                        (customer_id, document_id, technology, vendor, vendor_id, category, 
                         criticality, sensitive_data, confidence, created_at, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                    """, (
                        customer_id,
                        doc_id,
                        tech,
                        name,
                        vendor_id,  # Set vendor_id FK to canonical vendor
                        "other",
                        criticality,
                        data_sensitivity in ["HIGH", "CRITICAL"],
                        risk_factors.get("privileged_access", False) and 90 or 70
                    ))
                
                created_vendors.append({
                    "customer_vendor_id": cv_id,
                    "profile_id": profile_id,
                    "vendor_id": vendor_id,
                    "name": name,
                    "action": "created"
                })
        
        # Process accepted customer technologies
        created_technologies = []
        skipped_technologies = []
        for item in confirmation.accepted_customer_technologies:
            idx = _resolve_index(item, customer_technologies)
            if idx is None or idx >= len(customer_technologies):
                skipped_technologies.append({"index": idx, "reason": "Index out of range"})
                continue
                
            tech = customer_technologies[idx]
            
            # If the item is a dict, use its fields directly
            if isinstance(item, dict):
                tech = {**tech, **{k: v for k, v in item.items() if k != "index" and v is not None}}
            
            # Apply edits
            edited = None
            if confirmation.edited_customer_technologies:
                for edited_tech in confirmation.edited_customer_technologies:
                    if edited_tech.get("index") == idx:
                        edited = edited_tech
                        break
                        
            name = edited.get("name") if edited else tech.get("name")
            category = edited.get("category") if edited else tech.get("category", "other")
            evidence = edited.get("evidence") if edited else tech.get("evidence", "")
            
            if not name:
                continue
                
            # Add to assets table for Technology Inventory (vendor_id = NULL for customer-owned)
            cur.execute("""
                INSERT INTO assets
                (customer_id, document_id, technology, category, 
                 criticality, data_sensitivity, confidence, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
            """, (
                customer_id,
                doc_id,
                name,
                category,
                "MEDIUM",
                "MEDIUM",
                tech.get("confidence", 70)
            ))
            
            created_technologies.append({"name": name})

        conn.commit()
        
        return {
            "success": True,
            "document_id": doc_id,
            "customer_id": customer_id,
            "created_vendors": created_vendors,
            "updated_vendors": updated_vendors,
            "created_technologies": created_technologies,
            "skipped_vendors": skipped_vendors,
            "total_processed": len(confirmation.accepted_vendors) + len(confirmation.accepted_customer_technologies),
        }
        
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()


@router.get("/risk-map")
def get_vendor_risk_map(current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    cur = conn.cursor()

    # Get all customers
    cur.execute("""
        SELECT id, name
        FROM customers WHERE id = %s;
    """, (current_user["customer_id"],))
    customers = cur.fetchall()

    # Get all unique vendors from customer_vendors
    cur.execute("""
        SELECT DISTINCT vendor
        FROM customer_vendors WHERE customer_id = %s;
    """, (current_user["customer_id"],))
    vendors = cur.fetchall()

    # Get customer-vendor relationships with assessment data
    cur.execute("""
        SELECT
            cv.id,
            cv.customer_id,
            c.name as customer_name,
            cv.vendor,
            cv.data_sensitivity AS criticality,
            a.id as assessment_id,
            a.severity,
            a.risk_score,
            e.title as cve_title,
            e.id as cve_id,
            a.created_at
        FROM customer_vendors cv
        JOIN customers c ON cv.customer_id = c.id
        LEFT JOIN assessments a ON cv.customer_id = a.customer_id
        LEFT JOIN cve_events e ON a.event_id = e.id
        WHERE cv.customer_id = %s
        ORDER BY a.created_at DESC NULLS LAST;
    """, (current_user["customer_id"],))
    relationships = cur.fetchall()

    cur.close()
    conn.close()

    # Build nodes
    nodes = []
    node_id_map = {}

    # Add customer nodes
    for cust in customers:
        node_id = f"customer-{cust[0]}"
        node_id_map[cust[0]] = node_id
        nodes.append({
            "id": node_id,
            "name": cust[1],
            "type": "customer",
            "riskScore": 0  # Will calculate below
        })

    # Add vendor nodes
    # NOTE: customerCount is computed as COUNT(DISTINCT customer_id) per vendor.
    # The relationships fetch below is a JOIN (customer_vendors x assessments x
    # cve_events) that yields multiple rows per customer-vendor pair (one per
    # assessment). We therefore track a SET of customer_ids per vendor and derive
    # the count from the set size, NOT by incrementing a counter per JOIN row.
    # (Incrementing per row would inflate the count to the number of assessments,
    # e.g. showing "7 customers" when there is really 1 customer.)
    vendor_customer_ids = {}
    for vendor in vendors:
        node_id = f"vendor-{vendor[0]}"
        nodes.append({
            "id": node_id,
            "name": vendor[0],
            "type": "vendor",
            "customerCount": 0  # Will calculate below
        })
        vendor_customer_ids[vendor[0]] = set()

    # Build links and calculate metrics
    links = []
    customer_risk_scores = {}
    customer_vendor_links = {}  # Track worst severity per customer-vendor pair

    for rel in relationships:
        cv_id, customer_id, customer_name, vendor, criticality, \
        assessment_id, severity, risk_score, cve_title, cve_id, created_at = rel

        # Count distinct customers per vendor (set-add, NOT per-row increment).
        if vendor in vendor_customer_ids and customer_id is not None:
            vendor_customer_ids[vendor].add(customer_id)

        # Track worst severity for this customer-vendor pair
        if customer_id in node_id_map and vendor:
            customer_node_id = node_id_map[customer_id]
            vendor_node_id = f"vendor-{vendor}"
            link_key = f"{customer_node_id}-{vendor_node_id}"

            if assessment_id:
                # Map severity to match frontend
                severity_map = {
                    'CRITICAL': 'critical',
                    'HIGH': 'high',
                    'MEDIUM': 'elevated',
                    'LOW': 'low'
                }
                severity_order = {'critical': 4, 'high': 3, 'elevated': 2, 'low': 1}
                mapped_severity = severity_map.get(severity, 'low')

                # Keep only the worst severity for this pair
                if link_key not in customer_vendor_links or \
                   severity_order.get(mapped_severity, 0) > severity_order.get(customer_vendor_links[link_key].get('severity', 'low'), 0):

                    # Calculate timestamp
                    if created_at:
                        from datetime import datetime
                        now = datetime.now()
                        diff = now - created_at
                        if diff.total_seconds() < 3600:
                            timestamp = f"{int(diff.total_seconds() / 60)}m ago"
                        elif diff.total_seconds() < 86400:
                            timestamp = f"{int(diff.total_seconds() / 3600)}h ago"
                        else:
                            timestamp = f"{diff.days}d ago"
                    else:
                        timestamp = "unknown"

                    customer_vendor_links[link_key] = {
                        "source": customer_node_id,
                        "target": vendor_node_id,
                        "severity": mapped_severity,
                        "cve": f"CVE-{cve_id}" if cve_id else "Unknown",
                        "riskScore": risk_score or 0,
                        "timestamp": timestamp
                    }

                # Accumulate customer risk scores
                if customer_id not in customer_risk_scores:
                    customer_risk_scores[customer_id] = []
                if risk_score:
                    customer_risk_scores[customer_id].append(risk_score)
            else:
                # Create a default link even without assessment
                if link_key not in customer_vendor_links:
                    customer_vendor_links[link_key] = {
                        "source": customer_node_id,
                        "target": vendor_node_id,
                        "severity": "low",
                        "cve": "No active findings",
                        "riskScore": 0,
                        "timestamp": "unknown"
                    }

    # Convert to links array
    links = list(customer_vendor_links.values())

    # Update customer risk scores (average)
    for node in nodes:
        if node["type"] == "customer":
            customer_id = int(node["id"].split("-")[1])
            if customer_id in customer_risk_scores and customer_risk_scores[customer_id]:
                node["riskScore"] = sum(customer_risk_scores[customer_id]) // len(customer_risk_scores[customer_id])
            else:
                node["riskScore"] = 0

    # Update vendor customer counts (distinct customer count derived from set size)
    for node in nodes:
        if node["type"] == "vendor":
            vendor_name = node["name"]
            node["customerCount"] = len(vendor_customer_ids.get(vendor_name, set()))

    return {
        "nodes": nodes,
        "links": links
    }
