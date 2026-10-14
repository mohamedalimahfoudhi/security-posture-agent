"""
Architecture Extraction Preview Service

Provides preview functionality for architecture document extraction
without committing to the database.
"""
import os
from typing import Dict, Any, List, Optional

from app.database.connection import get_connection
from app.document_processor import DocumentProcessor
from app.ai.technology_extractor import TechnologyExtractor


class ArchitecturePreviewService:
    """Service for previewing architecture extraction before committing."""
    
    @staticmethod
    def preview_extraction(document_id: int, customer_id: int) -> Dict[str, Any]:
        """
        Preview technology extraction from an architecture document without committing.
        
        Returns:
            Dictionary with extracted technologies, services, and preview metadata
        """
        conn = get_connection()
        cur = conn.cursor()
        
        try:
            # Load the document (tenant-checked)
            cur.execute("""
                SELECT id, filename, file_type, file_path, extraction_status, customer_id
                FROM documents
                WHERE id = %s AND customer_id = %s
            """, (document_id, customer_id))
            
            row = cur.fetchone()
            if not row:
                raise ValueError(f"Document {document_id} not found for customer {customer_id}")
            
            document = {
                "id": row[0],
                "filename": row[1],
                "file_type": row[2],
                "file_path": row[3],
                "extraction_status": row[4],
                "customer_id": row[5],
            }
            
            file_path = document["file_path"]
            file_type = document["file_type"]
            filename = document["filename"]
            
            # Ensure the file exists
            if not os.path.exists(file_path):
                raise ValueError(f"Document file missing at {file_path}")
            
            # Extract text using DocumentProcessor
            processor = DocumentProcessor()
            text_content = processor.extract_text(file_path, file_type)
            
            if not text_content or len(text_content.strip()) < 10:
                raise ValueError("Could not extract sufficient text from the architecture document")
            
            # Extract technologies using TechnologyExtractor
            extractor = TechnologyExtractor()
            result = extractor.extract_from_text(text_content, filename)
            
            if result.get("status") == "failed":
                raise ValueError(result.get("reason", "Technology extraction failed"))
            
            assets = result.get("assets", [])
            
            # Derive services from assets
            CATEGORY_TO_SERVICE_TYPE = {
                "cloud_provider": "Cloud Service",
                "web_server": "Web Service",
                "database": "Data Service",
                "security_tools": "Security Service",
                "monitoring": "Monitoring Service",
                "container": "Container Service",
                "devops": "DevOps Service",
                "network_devices": "Network Service",
                "other": "Managed Service",
            }
            
            SAAS_SERVICE_KEYWORDS = [
                "microsoft 365", "office 365", "azure ad", "aws", "amazon web services",
                "google cloud", "salesforce", "servicenow", "workday", "okta",
                "active directory", "exchange online", "sharepoint online", "teams",
                "auto", "sap", "oracle cloud", "dropbox", "slack", "zoom",
            ]
            
            def _is_service_like(tech_name: str, category: str) -> bool:
                name_lower = (tech_name or "").lower().strip()
                if not name_lower:
                    return False
                if category == "cloud_provider":
                    return True
                for keyword in SAAS_SERVICE_KEYWORDS:
                    if keyword in name_lower:
                        return True
                return False
            
            new_services = []
            service_names = set()
            for asset in assets:
                tech_name = asset.get("technology")
                category = (asset.get("category") or "other").lower()
                if _is_service_like(tech_name, category):
                    svc = tech_name or ""
                    if svc and svc not in service_names:
                        service_names.add(svc)
                        new_services.append({
                            "service_name": svc,
                            "service_type": CATEGORY_TO_SERVICE_TYPE.get(category, "Managed Service"),
                        })
            
            return {
                "document_id": document_id,
                "filename": filename,
                "file_type": file_type,
                "technologies_extracted": len(assets),
                "technologies": assets,
                "services_extracted": len(new_services),
                "services": new_services,
                "extraction_status": "success",
            }
            
        finally:
            cur.close()
            conn.close()
    
    @staticmethod
    def get_current_profile_state(customer_vendor_id: int) -> Dict[str, Any]:
        """
        Get the current state of a profile for comparison.
        
        Returns:
            Dictionary with current technologies and services
        """
        conn = get_connection()
        cur = conn.cursor()
        
        try:
            # Get profile ID
            cur.execute(
                "SELECT id FROM third_party_profiles WHERE customer_vendor_id = %s",
                (customer_vendor_id,),
            )
            profile_row = cur.fetchone()
            
            if not profile_row:
                return {
                    "profile_id": None,
                    "technologies": [],
                    "services": [],
                }
            
            profile_id = profile_row[0]
            
            # Load current technologies
            cur.execute("""
                SELECT technology, version, category
                FROM third_party_profile_technologies
                WHERE profile_id = %s
            """, (profile_id,))
            technologies = [
                {"technology": r[0], "version": r[1], "category": r[2]}
                for r in cur.fetchall()
            ]
            
            # Load current services
            cur.execute("""
                SELECT service_name, service_type
                FROM third_party_profile_services
                WHERE profile_id = %s
            """, (profile_id,))
            services = [
                {"service_name": r[0], "service_type": r[1]}
                for r in cur.fetchall()
            ]
            
            return {
                "profile_id": profile_id,
                "technologies": technologies,
                "services": services,
            }
            
        finally:
            cur.close()
            conn.close()
