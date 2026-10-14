"""
Vendor Resolution Service

Resolves vendor names against the global vendors and vendor_aliases tables.
Provides canonical vendor IDs for customer-vendor relationships.
"""
from typing import Optional, Tuple
from app.database.connection import get_connection
import re


class VendorResolutionService:
    """Service for resolving vendor names to canonical vendor IDs."""
    
    @staticmethod
    def normalize_vendor_name(name: str) -> str:
        """Normalize vendor name for comparison."""
        if not name:
            return ""
        # Convert to lowercase, trim, remove extra spaces
        normalized = name.lower().strip()
        # Remove common punctuation
        normalized = re.sub(r'[.,;:\-_]', '', normalized)
        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', normalized)
        return normalized
    
    @staticmethod
    def resolve_vendor(vendor_name: str) -> Tuple[Optional[int], Optional[str], float]:
        """
        Resolve a vendor name to a canonical vendor ID.
        
        Returns:
            (vendor_id, canonical_name, confidence)
            
        Resolution priority:
        1. Exact canonical vendor ID match (if input is numeric ID)
        2. Exact vendor name match (case-insensitive)
        3. Alias match (case-insensitive)
        4. Normalized text match
        """
        if not vendor_name:
            return None, None, 0.0
        
        conn = get_connection()
        cur = conn.cursor()
        
        try:
            # Priority 1: Check if input is a numeric vendor ID
            if vendor_name.isdigit():
                cur.execute("SELECT id, name FROM vendors WHERE id = %s", (int(vendor_name),))
                result = cur.fetchone()
                if result:
                    return result[0], result[1], 1.0
            
            # Priority 2: Exact vendor name match (case-insensitive)
            cur.execute("SELECT id, name FROM vendors WHERE LOWER(name) = LOWER(%s)", (vendor_name,))
            result = cur.fetchone()
            if result:
                return result[0], result[1], 1.0
            
            # Priority 3: Alias match (case-insensitive)
            cur.execute("""
                SELECT v.id, v.name 
                FROM vendor_aliases va
                JOIN vendors v ON v.id = va.vendor_id
                WHERE LOWER(va.alias) = LOWER(%s)
            """, (vendor_name,))
            result = cur.fetchone()
            if result:
                return result[0], result[1], 0.95
            
            # Priority 4: Normalized text match
            normalized_input = VendorResolutionService.normalize_vendor_name(vendor_name)
            
            # Check against normalized vendor names
            cur.execute("SELECT id, name FROM vendors")
            all_vendors = cur.fetchall()
            
            for vendor_id, vendor_name in all_vendors:
                normalized_vendor = VendorResolutionService.normalize_vendor_name(vendor_name)
                if normalized_input == normalized_vendor:
                    return vendor_id, vendor_name, 0.85
            
            # Check against normalized aliases
            cur.execute("""
                SELECT v.id, v.name, va.alias
                FROM vendor_aliases va
                JOIN vendors v ON v.id = va.vendor_id
            """)
            all_aliases = cur.fetchall()
            
            for vendor_id, vendor_name, alias in all_aliases:
                normalized_alias = VendorResolutionService.normalize_vendor_name(alias)
                if normalized_input == normalized_alias:
                    return vendor_id, vendor_name, 0.80
            
            # No match found
            return None, None, 0.0
            
        finally:
            cur.close()
            conn.close()
    
    @staticmethod
    def create_vendor(vendor_name: str, category: str = "UNKNOWN", base_risk_score: int = 50) -> Tuple[int, str]:
        """
        Create a new vendor in the global vendors table.
        
        Returns:
            (vendor_id, canonical_name)
        """
        conn = get_connection()
        cur = conn.cursor()
        
        try:
            cur.execute("""
                INSERT INTO vendors (name, category, base_risk_score)
                VALUES (%s, %s, %s)
                RETURNING id
            """, (vendor_name, category, base_risk_score))
            
            vendor_id = cur.fetchone()[0]
            conn.commit()
            
            return vendor_id, vendor_name
            
        finally:
            cur.close()
            conn.close()
    
    @staticmethod
    def get_or_create_vendor(vendor_name: str, category: str = "UNKNOWN", 
                            base_risk_score: int = 50, 
                            auto_create: bool = False) -> Tuple[Optional[int], Optional[str], bool, float]:
        """
        Get existing vendor or create a new one.
        
        Returns:
            (vendor_id, canonical_name, was_created, confidence)
            
        If auto_create is True and no match is found, creates a new vendor.
        If auto_create is False and no match is found, returns (None, None, False, 0.0).
        """
        # Try to resolve existing vendor
        vendor_id, canonical_name, confidence = VendorResolutionService.resolve_vendor(vendor_name)
        
        if vendor_id:
            return vendor_id, canonical_name, False, confidence
        
        # No match found
        if auto_create:
            vendor_id, canonical_name = VendorResolutionService.create_vendor(
                vendor_name, category, base_risk_score
            )
            return vendor_id, canonical_name, True, 1.0
        
        return None, None, False, 0.0
    
    @staticmethod
    def add_alias(vendor_id: int, alias: str) -> bool:
        """
        Add an alias for a vendor.
        
        Returns:
            True if successful, False if alias already exists
        """
        conn = get_connection()
        cur = conn.cursor()
        
        try:
            # Check if alias already exists
            cur.execute("""
                SELECT 1 FROM vendor_aliases 
                WHERE vendor_id = %s AND LOWER(alias) = LOWER(%s)
            """, (vendor_id, alias))
            
            if cur.fetchone():
                return False
            
            # Add alias
            cur.execute("""
                INSERT INTO vendor_aliases (vendor_id, alias)
                VALUES (%s, %s)
            """, (vendor_id, alias))
            
            conn.commit()
            return True
            
        finally:
            cur.close()
            conn.close()
