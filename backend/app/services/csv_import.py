"""
CSV/Excel Import Service for Third-Party Vendors

Handles bulk import of customer-vendor relationships from CSV or Excel files.
"""
import csv
import io
from typing import List, Dict, Tuple, Optional
from app.database.connection import get_connection
from app.services.vendor_resolution import VendorResolutionService


class CSVImportService:
    """Service for importing customer-vendor relationships from CSV/Excel files."""
    
    REQUIRED_COLUMNS = ['customer', 'vendor']
    OPTIONAL_COLUMNS = [
        'relationship_type',
        'business_role',
        'criticality',
        'data_sensitivity',
        'data_access_level',
        'privileged_access',
        'technology',
        'version',
        'notes',
        'sla_penalty_risk',
        'regulatory_flags'
    ]
    
    @staticmethod
    def parse_csv(file_content: str) -> List[Dict[str, str]]:
        """
        Parse CSV file content into a list of dictionaries.
        
        Returns:
            List of row dictionaries
        """
        # Strip leading/trailing whitespace
        file_content = file_content.strip()
        
        # Parse CSV
        reader = csv.DictReader(io.StringIO(file_content))
        rows = list(reader)
        
        # Validate that rows are dictionaries
        validated_rows = []
        for row in rows:
            if isinstance(row, dict):
                validated_rows.append(row)
            else:
                # If row is not a dict, skip it or handle error
                continue
        
        return validated_rows
    
    @staticmethod
    def validate_row(row: Dict[str, str]) -> Tuple[bool, Optional[str], Dict[str, str]]:
        """
        Validate a single row of CSV data.
        
        Returns:
            (is_valid, error_message, normalized_row)
        """
        normalized = {}
        
        # Check required columns
        if not row.get('customer'):
            return False, "Missing required column: customer", {}
        if not row.get('vendor'):
            return False, "Missing required column: vendor", {}
        
        # Normalize and validate columns
        normalized['customer'] = row['customer'].strip()
        normalized['vendor'] = row['vendor'].strip()
        normalized['relationship_type'] = row.get('relationship_type', 'Technology Provider').strip()
        normalized['business_role'] = row.get('business_role', '').strip()
        normalized['criticality'] = row.get('criticality', 'MEDIUM').strip().upper()
        normalized['data_sensitivity'] = row.get('data_sensitivity', 'MEDIUM').strip().upper()
        normalized['data_access_level'] = row.get('data_access_level', '').strip().upper()
        normalized['privileged_access'] = row.get('privileged_access', 'false').strip().lower() == 'true'
        normalized['technology'] = row.get('technology', '').strip()
        normalized['version'] = row.get('version', '').strip()
        normalized['notes'] = row.get('notes', '').strip()
        normalized['sla_penalty_risk'] = None
        normalized['regulatory_flags'] = []
        
        # Parse optional numeric fields
        if row.get('sla_penalty_risk'):
            try:
                normalized['sla_penalty_risk'] = int(row['sla_penalty_risk'])
            except ValueError:
                return False, "Invalid sla_penalty_risk: must be integer", {}
        
        # Parse regulatory flags (comma-separated)
        if row.get('regulatory_flags'):
            flags = row['regulatory_flags'].split(',')
            normalized['regulatory_flags'] = [f.strip() for f in flags if f.strip()]
        
        # Validate criticality values
        valid_criticality = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        if normalized['criticality'] not in valid_criticality:
            return False, f"Invalid criticality: {normalized['criticality']}", {}
        
        # Validate data_sensitivity values
        valid_sensitivity = ['LOW', 'MEDIUM', 'HIGH', 'SENSITIVE']
        if normalized['data_sensitivity'] not in valid_sensitivity:
            return False, f"Invalid data_sensitivity: {normalized['data_sensitivity']}", {}
        
        return True, None, normalized
    
    @staticmethod
    def preview_import(rows: List[Dict[str, str]], customer_id: int, 
                       auto_create_vendor: bool = False) -> Dict:
        """
        Preview the import without committing to database.
        
        Returns:
            Dictionary with validation results
        """
        valid_rows = []
        invalid_rows = []
        warnings = []
        
        for idx, row in enumerate(rows, start=1):
            is_valid, error, normalized = CSVImportService.validate_row(row)
            
            if not is_valid:
                invalid_rows.append({
                    'row_number': idx,
                    'error': error,
                    'data': row
                })
                continue
            
            # Resolve customer
            conn = get_connection()
            cur = conn.cursor()
            try:
                cur.execute("SELECT id FROM customers WHERE name = %s", (normalized['customer'],))
                customer = cur.fetchone()
                
                if not customer:
                    invalid_rows.append({
                        'row_number': idx,
                        'error': f"Customer not found: {normalized['customer']}",
                        'data': row
                    })
                    continue
                
                # Resolve vendor
                vendor_id, canonical_name, was_created, confidence = VendorResolutionService.get_or_create_vendor(
                    normalized['vendor'],
                    auto_create=auto_create_vendor
                )
                
                if not vendor_id:
                    invalid_rows.append({
                        'row_number': idx,
                        'error': f"Vendor not found: {normalized['vendor']}",
                        'data': row
                    })
                    continue
                
                # Check for duplicate relationship
                cur.execute("""
                    SELECT id FROM customer_vendors
                    WHERE customer_id = %s AND vendor_id = %s
                """, (customer[0], vendor_id))
                
                if cur.fetchone():
                    warnings.append({
                        'row_number': idx,
                        'warning': f"Relationship already exists: {normalized['customer']} -> {canonical_name}",
                        'data': normalized
                    })
                    continue
                
                valid_rows.append({
                    'row_number': idx,
                    'customer_id': customer[0],
                    'customer_name': normalized['customer'],
                    'vendor_id': vendor_id,
                    'vendor_name': canonical_name,
                    'data': normalized,
                    'vendor_created': was_created,
                    'resolution_confidence': confidence
                })
                
            finally:
                cur.close()
                conn.close()
        
        return {
            'total_rows': len(rows),
            'valid_rows': len(valid_rows),
            'invalid_rows': len(invalid_rows),
            'warnings': len(warnings),
            'valid_data': valid_rows,
            'invalid_data': invalid_rows,
            'warnings_data': warnings
        }
    
    @staticmethod
    def commit_import(valid_rows: List[Dict], customer_id: int) -> Dict:
        """
        Commit the validated import to the database.
        
        Returns:
            Dictionary with import results
        """
        conn = get_connection()
        cur = conn.cursor()
        
        created_relationships = []
        created_profiles = []
        errors = []
        
        try:
            for row in valid_rows:
                try:
                    # Ensure row is a dictionary
                    if not isinstance(row, dict):
                        errors.append({
                            'row_number': row.get('row_number', 'unknown') if isinstance(row, dict) else 'unknown',
                            'error': f"Invalid row format: {type(row)}",
                            'data': row
                        })
                        continue
                    
                    # Insert customer-vendor relationship
                    cur.execute("""
                        INSERT INTO customer_vendors
                        (customer_id, vendor_id, vendor, technology, criticality,
                         relationship_type, data_sensitivity, confidence, notes,
                         sla_penalty_risk, regulatory_flags, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                        RETURNING id
                    """, (
                        row['customer_id'],
                        row['vendor_id'],
                        row['vendor_name'],
                        row['data']['technology'],
                        row['data']['criticality'],
                        row['data']['relationship_type'],
                        row['data']['data_sensitivity'],
                        100,  # default confidence
                        row['data']['notes'],
                        row['data']['sla_penalty_risk'],
                        row['data']['regulatory_flags']
                    ))
                    
                    cv_id = cur.fetchone()[0]
                    created_relationships.append(cv_id)
                    
                    # Create profile
                    cur.execute("""
                        INSERT INTO third_party_profiles
                        (customer_vendor_id, business_role, data_access_level,
                         privileged_access, criticality, risk_score)
                        VALUES (%s, %s, %s, %s, %s, 0)
                        RETURNING id
                    """, (
                        cv_id,
                        row['data']['business_role'],
                        row['data']['data_access_level'],
                        row['data']['privileged_access'],
                        row['data']['criticality']
                    ))
                    
                    profile_id = cur.fetchone()[0]
                    created_profiles.append(profile_id)
                    
                except Exception as e:
                    errors.append({
                        'row_number': row['row_number'],
                        'error': str(e),
                        'data': row
                    })
                    conn.rollback()
                    raise
            
            conn.commit()
            
            return {
                'success': True,
                'created_relationships': len(created_relationships),
                'created_profiles': len(created_profiles),
                'errors': errors,
                'relationship_ids': created_relationships,
                'profile_ids': created_profiles
            }
            
        except Exception as e:
            conn.rollback()
            return {
                'success': False,
                'error': str(e),
                'created_relationships': len(created_relationships),
                'created_profiles': len(created_profiles),
                'errors': errors
            }
        finally:
            cur.close()
            conn.close()
