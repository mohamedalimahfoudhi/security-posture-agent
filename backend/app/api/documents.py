from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from app.auth.deps import get_current_user, require_roles
from fastapi.responses import JSONResponse
from app.document_processor import DocumentProcessor
from app.database.connection import get_connection
import os
import json
import uuid
import time
import logging
import asyncio
from datetime import datetime
import psycopg2.extras

# Set up logging with file handler
import logging
import sys

# Create file handler
file_handler = logging.FileHandler('backend.log', encoding='utf-8')
file_handler.setLevel(logging.INFO)

# Create console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)

# Create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Get root logger and configure
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.addHandler(file_handler)
root_logger.addHandler(console_handler)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/documents",
    tags=["Documents"]
)

# Create uploads directory if it doesn't exist
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@router.post("/upload")
async def upload_document(
    file: UploadFile = File(...),
    current_user: dict = Depends(require_roles("Admin", "Analyst"))
):
    """Upload a document for architecture analysis"""
    
    customer_id = current_user["customer_id"]
    logger.info(f"[UPLOAD] Starting upload for file: {file.filename}, customer_id: {customer_id}")
    start_time = time.time()
    
    try:
        # Validate file type
        allowed_types = ['pdf', 'docx', 'xlsx', 'txt']
        file_extension = file.filename.split('.')[-1].lower()
        
        if file_extension not in allowed_types:
            logger.error(f"[UPLOAD] Invalid file type: {file_extension}")
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type. Allowed: {', '.join(allowed_types)}"
            )
        
        logger.info(f"[UPLOAD] File type validated: {file_extension}")
        
        # Generate unique filename
        unique_filename = f"{uuid.uuid4()}_{file.filename}"
        file_path = os.path.join(UPLOAD_DIR, unique_filename)
        
        # Save file
        logger.info(f"[UPLOAD] Saving file to: {file_path}")
        with open(file_path, 'wb') as buffer:
            content = await file.read()
            buffer.write(content)
        
        # Get file size
        file_size = len(content)
        logger.info(f"[UPLOAD] File saved successfully, size: {file_size} bytes")
        
        # Store document record in database
        conn = get_connection()
        cur = conn.cursor()
        
        cur.execute("""
            INSERT INTO documents 
            (customer_id, filename, file_type, file_size, file_path, upload_status, uploaded_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            customer_id,
            file.filename,
            file_extension,
            file_size,
            file_path,
            'uploaded',
            datetime.now()
        ))
        
        document_id = cur.fetchone()[0]
        conn.commit()
        
        cur.close()
        conn.close()
        
        upload_time = time.time() - start_time
        logger.info(f"[UPLOAD] ========================================")
        logger.info(f"[UPLOAD] Document uploaded successfully")
        logger.info(f"[UPLOAD] Document ID: {document_id}")
        logger.info(f"[UPLOAD] Filename: {file.filename}")
        logger.info(f"[UPLOAD] Customer ID: {customer_id}")
        logger.info(f"[UPLOAD] Upload duration: {upload_time:.2f}s")
        logger.info(f"[UPLOAD] ========================================")
        
        return {
            "id": document_id,
            "filename": file.filename,
            "file_type": file_extension,
            "file_size": file_size,
            "upload_status": "uploaded",
            "message": "Document uploaded successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[UPLOAD] Upload failed: {e}")
        # Clean up file if database insert failed
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@router.post("/extract/{document_id}")
async def extract_technologies(document_id: int, current_user: dict = Depends(require_roles("Admin", "Analyst"))):
    """Extract technologies from uploaded document using AI"""
    
    logger.info(f"[DOCUMENT EXTRACTION] ========================================")
    logger.info(f"[DOCUMENT EXTRACTION] Starting extraction for document_id: {document_id}")
    start_time = time.time()
    
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        # Get document record
        cur.execute("""
            SELECT id, filename, file_type, file_path, extraction_status, customer_id
            FROM documents
            WHERE id = %s AND customer_id = %s
        """, (document_id, current_user["customer_id"]))
        
        document = cur.fetchone()
        
        if not document:
            logger.error(f"[DOCUMENT EXTRACTION] Document not found: {document_id}")
            cur.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Document not found")
        
        doc_id, filename, file_type, file_path, extraction_status, customer_id = document
        logger.info(f"[DOCUMENT EXTRACTION] ========================================")
        logger.info(f"[DOCUMENT EXTRACTION] Starting extraction process")
        logger.info(f"[DOCUMENT EXTRACTION] Document ID: {document_id}")
        logger.info(f"[DOCUMENT EXTRACTION] Filename: {filename}")
        logger.info(f"[DOCUMENT EXTRACTION] File type: {file_type}")
        logger.info(f"[DOCUMENT EXTRACTION] File path: {file_path}")
        logger.info(f"[DOCUMENT EXTRACTION] Current status: {extraction_status}")
        logger.info(f"[DOCUMENT EXTRACTION] Customer ID: {customer_id}")
        logger.info(f"[DOCUMENT EXTRACTION] ========================================")
        
        # Check if already extracted
        if extraction_status == 'completed':
            logger.info(f"[DOCUMENT EXTRACTION] Document already processed, skipping")
            cur.close()
            conn.close()
            return {"message": "Document already processed", "document_id": document_id}
        
        logger.info(f"[DOCUMENT EXTRACTION] ========================================")
        logger.info(f"[PROCESSING] Starting text extraction")
        
        # Update status to extracting
        cur.execute("""
            UPDATE documents
            SET extraction_status = 'extracting'
            WHERE id = %s
        """, (document_id,))
        conn.commit()
        logger.info(f"[PROCESSING] Status updated to 'extracting'")
        
        # Extract text from document (run in thread pool to avoid blocking event loop)
        processor = DocumentProcessor()
        text_content = await asyncio.wait_for(
            asyncio.to_thread(processor.extract_text, file_path, file_type),
            timeout=30
        )
        
        if not text_content or len(text_content.strip()) < 50:
            logger.error(f"[PROCESSING] Insufficient text content extracted: {len(text_content) if text_content else 0} characters")
            cur.execute("""
                UPDATE documents
                SET extraction_status = 'failed',
                    error_message = 'Could not extract sufficient text content',
                    processed_at = %s
                WHERE id = %s
            """, (datetime.now(), document_id))
            conn.commit()
            cur.close()
            conn.close()
            raise HTTPException(status_code=400, detail="Could not extract sufficient text content")
        
        logger.info(f"[PROCESSING] Text extraction completed")
        logger.info(f"[PROCESSING] Characters extracted: {len(text_content)}")
        logger.info(f"[PROCESSING] First 200 characters: {text_content[:200]}")
        
        # Update status to analyzing
        cur.execute("""
            UPDATE documents
            SET extraction_status = 'analyzing'
            WHERE id = %s
        """, (document_id,))
        conn.commit()
        logger.info(f"[PROCESSING] Status updated to 'analyzing'")
        
        logger.info(f"[DOCUMENT EXTRACTION] ========================================")
        logger.info(f"[AI EXTRACTION] Starting AI technology extraction")
        
        # Use AI to extract technologies (run in thread pool to avoid blocking event loop)
        from app.ai.technology_extractor import TechnologyExtractor
        extractor = TechnologyExtractor()
        extracted_assets = await asyncio.wait_for(
            asyncio.to_thread(extractor.extract_from_text, text_content, filename),
            timeout=300  # Allow time for primary (90s) + fallback (180s) + overhead
        )
        
        logger.info(f"[AI EXTRACTION] AI extraction completed")
        
        # Check if AI extraction failed
        if extracted_assets.get("status") == "failed":
            error_reason = extracted_assets.get("reason", "Unknown AI error")
            model_used = extracted_assets.get("model", "unknown")
            logger.error(f"[AI EXTRACTION] ✗ Extraction failed: {error_reason} (model: {model_used})")
            
            cur.execute("""
                UPDATE documents
                SET extraction_status = 'failed',
                    error_message = %s,
                    processed_at = %s
                WHERE id = %s
            """, (f"AI extraction failed: {error_reason}", datetime.now(), document_id))
            conn.commit()
            cur.close()
            conn.close()
            
            raise HTTPException(
                status_code=502,
                detail={
                    "status": "failed",
                    "reason": error_reason,
                    "model": model_used,
                    "document_id": document_id
                }
            )
        
        logger.info(f"[AI EXTRACTION] Assets detected: {len(extracted_assets.get('assets', []))}")
        
        # Store extracted assets
        assets_inserted = 0
        assets_failed = 0
        
        logger.info(f"[DOCUMENT EXTRACTION] ========================================")
        logger.info(f"[ASSET CREATION] Starting asset insertion")
        
        for asset in extracted_assets.get('assets', []):
            try:
                # Check for duplicate asset (same technology, vendor, version for this customer)
                cur.execute("""
                    SELECT id FROM assets
                    WHERE customer_id = %s
                    AND technology = %s
                    AND (vendor = %s OR (vendor IS NULL AND %s IS NULL))
                    AND (version = %s OR (version IS NULL AND %s IS NULL))
                """, (
                    customer_id,
                    asset.get('technology'),
                    asset.get('vendor'),
                    asset.get('vendor'),
                    asset.get('version'),
                    asset.get('version')
                ))
                
                existing_asset = cur.fetchone()
                if existing_asset:
                    logger.info(f"[ASSET CREATION] Duplicate asset found: {asset.get('technology')} ({asset.get('vendor')}) - skipping")
                    continue
                
                cur.execute("""
                    INSERT INTO assets
                    (customer_id, document_id, technology, vendor, version,
                     criticality, internet_exposed, sensitive_data, category,
                     operating_system, database, cloud_provider, web_server,
                     firewall, virtualization, programming_language, framework,
                     security_tools, network_devices, confidence, extraction_metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    customer_id,
                    document_id,
                    asset.get('technology'),
                    asset.get('vendor'),
                    asset.get('version'),
                    asset.get('criticality', 'MEDIUM'),
                    asset.get('internet_exposed', False),
                    asset.get('sensitive_data', False),
                    asset.get('category'),
                    asset.get('operating_system'),
                    asset.get('database'),
                    asset.get('cloud_provider'),
                    asset.get('web_server'),
                    asset.get('firewall'),
                    asset.get('virtualization'),
                    asset.get('programming_language'),
                    asset.get('framework'),
                    asset.get('security_tools'),
                    asset.get('network_devices'),
                    asset.get('confidence', 80),
                    psycopg2.extras.Json({'source': 'ai_extraction', 'model': extracted_assets.get('model', 'unknown')})
                ))
                assets_inserted += 1
                logger.info(f"[ASSET CREATION] Inserted: {asset.get('technology')} (vendor: {asset.get('vendor') or 'None'})")
            except Exception as e:
                logger.error(f"[ASSET CREATION] Failed to insert asset: {e}")
                assets_failed += 1
                continue
        
        logger.info(f"[ASSET CREATION] Asset insertion completed")
        logger.info(f"[ASSET CREATION] Assets inserted: {assets_inserted}")
        logger.info(f"[ASSET CREATION] Assets failed: {assets_failed}")
        
        # Commit asset insertions to ensure they persist even if correlation fails
        conn.commit()
        logger.info(f"[ASSET CREATION] Assets committed to database")
        
        # Trigger correlation with CVEs and create assessments
        logger.info(f"[DOCUMENT EXTRACTION] ========================================")
        logger.info(f"[CORRELATION] Starting asset-CVE correlation")
        
        try:
            from app.database.assessment_repository import check_asset_match, insert_assessment
            from app.database.repository import get_cves
            
            # Get all CVEs from database
            cves = get_cves()
            logger.info(f"[CORRELATION] Found {len(cves)} CVEs in database")
            
            # Get customer's assets for correlation
            from app.database.assessment_repository import get_assets_for_customer
            customer_assets = get_assets_for_customer(customer_id)
            logger.info(f"[CORRELATION] Found {len(customer_assets)} assets for customer {customer_id}")
            
            assessments_created = 0
            for cve in cves:
                cve_id = cve[0]
                cve_title = cve[1]
                cve_severity = cve[2]
                cve_cvss = cve[3]
                cve_published = cve[4]
                
                # Check if this CVE matches any extracted assets
                asset_match = check_asset_match(cve_title, None, customer_id)
                
                if asset_match:
                    logger.info(f"[CORRELATION] Match found: CVE {cve_id} matches asset {asset_match['asset']['technology']}")
                    
                    # Prepare basic assessment data
                    assessment_data = {
                        "customer_id": customer_id,
                        "event_id": cve_id,
                        "cve_title": cve_title,
                        "cve_technology": None,
                        "vendor": asset_match['asset'].get('vendor'),
                        "technology": asset_match['asset'].get('technology'),
                        "assessment": {
                            "threat_summary": f"Vulnerability {cve_title} affects detected technology {asset_match['asset']['technology']}",
                            "severity": cve_severity,
                            "risk_score": cve_cvss or 7.0,
                            "exploitation_risk": "HIGH" if cve_severity in ['CRITICAL', 'HIGH'] else "MEDIUM",
                            "recommendations": [
                                "Update to latest version",
                                "Apply security patches",
                                "Monitor for exploitation attempts"
                            ]
                        }
                    }
                    
                    # Enhance with AI analysis
                    try:
                        from app.ai.assessment_agent import generate_assessment
                        
                        logger.info(f"[AI ASSESSMENT REQUEST] ========================================")
                        logger.info(f"[AI ASSESSMENT REQUEST] Analyzing CVE {cve_id}")
                        logger.info(f"[AI ASSESSMENT REQUEST] CVE Title: {cve_title}")
                        logger.info(f"[AI ASSESSMENT REQUEST] Matched Asset: {asset.get('technology')} (vendor: {asset.get('vendor')}, version: {asset.get('version')})")
                        logger.info(f"[AI ASSESSMENT REQUEST] CVSS Score: {cve_cvss}")
                        logger.info(f"[AI ASSESSMENT REQUEST] ========================================")
                        
                        # Call the proper assessment function
                        generate_assessment(cve_id, cve_title, cve_severity, customer_id)
                        
                        logger.info(f"[AI ASSESSMENT SUCCESS] ========================================")
                        logger.info(f"[AI ASSESSMENT SUCCESS] Assessment created for CVE {cve_id}")
                        logger.info(f"[AI ASSESSMENT SUCCESS] ========================================")
                        
                    except Exception as e:
                        logger.error(f"[AI ANALYSIS] AI analysis error for CVE {cve_id}: {e}")
                        # Continue with basic assessment if AI fails
            
            logger.info(f"[CORRELATION] Correlation completed: {assessments_created} assessments created")
            
        except Exception as e:
            logger.error(f"[CORRELATION] Correlation failed: {e}")
            import traceback
            logger.error(f"[CORRELATION] Traceback: {traceback.format_exc()}")

        # Update document status to completed
        cur.execute("""
            UPDATE documents
            SET extraction_status = 'completed',
                processed_at = %s
            WHERE id = %s
        """, (datetime.now(), document_id))
        
        conn.commit()
        cur.close()
        conn.close()
        
        total_time = time.time() - start_time
        logger.info(f"[DOCUMENT EXTRACTION] ========================================")
        logger.info(f"[DOCUMENT EXTRACTION] Extraction completed successfully")
        logger.info(f"[DOCUMENT EXTRACTION] Document ID: {document_id}")
        logger.info(f"[DOCUMENT EXTRACTION] Total duration: {total_time:.2f}s")
        logger.info(f"[DOCUMENT EXTRACTION] Assets created: {assets_inserted}")
        logger.info(f"[DOCUMENT EXTRACTION] Assets failed: {assets_failed}")
        logger.info(f"[DOCUMENT EXTRACTION] Assessments created: {assessments_created}")
        logger.info(f"[DOCUMENT EXTRACTION] ========================================")
        
        return {
            "document_id": document_id,
            "assets_extracted": assets_inserted,
            "message": "Technology extraction completed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[DOCUMENT EXTRACTION] ========================================")
        logger.error(f"[DOCUMENT EXTRACTION] Extraction failed")
        logger.error(f"[DOCUMENT EXTRACTION] Document ID: {document_id}")
        logger.error(f"[DOCUMENT EXTRACTION] Error: {e}")
        import traceback
        logger.error(f"[DOCUMENT EXTRACTION] Traceback: {traceback.format_exc()}")
        logger.error(f"[DOCUMENT EXTRACTION] ========================================")
        
        # Update document status to failed
        try:
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("""
                UPDATE documents
                SET extraction_status = 'failed',
                    error_message = %s,
                    processed_at = %s
                WHERE id = %s
            """, (str(e), datetime.now(), document_id))
            conn.commit()
            cur.close()
            conn.close()
        except Exception as db_error:
            logger.error(f"[DOCUMENT EXTRACTION] Failed to update error status: {db_error}")
        
        raise HTTPException(status_code=500, detail=f"Extraction failed: {str(e)}")


@router.delete("/{document_id}")
async def delete_document(document_id: int, current_user: dict = Depends(get_current_user)):
    """Delete a document and its associated extracted assets"""
    
    customer_id = current_user["customer_id"]
    logger.info(f"[DOCUMENT DELETION] Starting deletion for document_id: {document_id}, customer_id: {customer_id}")
    
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        # Verify document exists and belongs to the customer
        cur.execute("""
            SELECT id, customer_id, file_path
            FROM documents
            WHERE id = %s
        """, (document_id,))
        
        document = cur.fetchone()
        
        if not document:
            cur.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Document not found")
            
        doc_id, doc_customer_id, file_path = document
        
        if doc_customer_id != customer_id:
            cur.close()
            conn.close()
            raise HTTPException(status_code=403, detail="Not authorized to delete this document")
            
        # 1. Delete related assessments first (linked through assets)
        logger.info(f"[DOCUMENT DELETION] Deleting related assessments...")
        cur.execute("""
            DELETE FROM assessments 
            WHERE asset_id IN (
                SELECT id FROM assets WHERE document_id = %s
            )
        """, (document_id,))
        assessments_deleted = cur.rowcount
        
        # 2. Delete related assets
        logger.info(f"[DOCUMENT DELETION] Deleting related assets...")
        cur.execute("""
            DELETE FROM assets 
            WHERE document_id = %s
        """, (document_id,))
        assets_deleted = cur.rowcount
        
        # 3. Delete the document record
        logger.info(f"[DOCUMENT DELETION] Deleting document record...")
        cur.execute("""
            DELETE FROM documents 
            WHERE id = %s
        """, (document_id,))
        
        # Commit transaction
        conn.commit()
        cur.close()
        conn.close()
        
        # 4. Safely remove physical file
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
                logger.info(f"[DOCUMENT DELETION] Removed file: {file_path}")
            except OSError as e:
                logger.error(f"[DOCUMENT DELETION] Failed to remove file {file_path}: {e}")
                # Don't fail the request if file deletion fails, DB is already clean
                
        logger.info(f"[DOCUMENT DELETION] Successfully deleted document {document_id}. Removed {assets_deleted} assets and {assessments_deleted} assessments.")
        
        return {
            "message": "Document deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[DOCUMENT DELETION] Failed to delete document: {e}")
        import traceback
        logger.error(f"[DOCUMENT DELETION] Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Deletion failed: {str(e)}")


@router.get("/")
async def get_documents(current_user: dict = Depends(get_current_user)):
    """Get all documents for a customer"""
    
    customer_id = current_user["customer_id"]
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT id, customer_id, filename, file_type, file_size, 
               upload_status, extraction_status, uploaded_at, processed_at
        FROM documents
        WHERE customer_id = %s
        ORDER BY uploaded_at DESC
    """, (customer_id,))
    
    documents = cur.fetchall()
    
    result = []
    for doc in documents:
        result.append({
            "id": doc[0],
            "customer_id": doc[1],
            "filename": doc[2],
            "file_type": doc[3],
            "file_size": doc[4],
            "upload_status": doc[5],
            "extraction_status": doc[6],
            "uploaded_at": doc[7],
            "processed_at": doc[8]
        })
    
    cur.close()
    conn.close()
    
    return result


@router.get("/{document_id}")
async def get_document(document_id: int, current_user: dict = Depends(get_current_user)):
    """Get a specific document"""
    
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT id, customer_id, filename, file_type, file_size, 
               upload_status, extraction_status, uploaded_at, processed_at, error_message
        FROM documents
        WHERE id = %s AND customer_id = %s
    """, (document_id, current_user["customer_id"]))
    
    document = cur.fetchone()
    
    if not document:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Document not found")
    
    result = {
        "id": document[0],
        "customer_id": document[1],
        "filename": document[2],
        "file_type": document[3],
        "file_size": document[4],
        "upload_status": document[5],
        "extraction_status": document[6],
        "uploaded_at": document[7],
        "processed_at": document[8],
        "error_message": document[9]
    }
    
    cur.close()
    conn.close()
    
    return result
