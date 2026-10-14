# Phase 2: Import Model Design

## Overview

Based on Phase 1 audit, the existing schema has the correct foundation but requires:
1. Creation of missing architecture tracking tables
2. Implementation of profile creation workflow
3. Integration of architecture document extraction into the import flow

## Target Architecture

```
THREAT INTELLIGENCE
    NVD CVE, Threat Articles, Breach Intelligence, Ransomware, Attack Techniques
        ↓
    threat_events
        ↓
    Vendor / Product / Technology Resolution
        ↓
    vendors (global canonical)
        ↓
    customer_vendors (customer-specific relationships)
        ↓
    third_party_profiles (customer-specific technical profile)
        ↓
    technologies (third_party_profile_technologies)
    services (third_party_profile_services)
        ↓
    Technology / Product / Version Matching
        ↓
    third_party_exposures
        ↓
    Customer-specific Risk
        ↓
    third_party_alerts
        ↓
    SOC Analyst Dashboard
```

## Data Model Design

### Global Vendor Identity (Existing - No Changes)

**vendors** (global canonical)
- id
- name
- category
- base_risk_score

**vendor_aliases** (existing - no changes)
- id
- vendor_id
- alias

### Customer-Specific Relationship (Existing - No Changes)

**customer_vendors** (existing - no changes)
- id
- customer_id
- vendor_id
- vendor (denormalized for display)
- relationship_type
- data_sensitivity
- notes
- technology
- criticality
- sla_penalty_risk
- regulatory_flags
- base_risk_score
- incident_count
- last_incident_date

### Technical Profile (Existing - No Schema Changes)

**third_party_profiles** (existing - no schema changes)
- id
- customer_vendor_id (FK to customer_vendors)
- business_role
- description
- data_access_level
- privileged_access
- criticality
- risk_score
- document_id (FK to documents)

**third_party_profile_technologies** (existing - no schema changes)
- id
- profile_id (FK to third_party_profiles)
- technology
- version
- category
- source

**third_party_profile_services** (existing - no schema changes)
- id
- profile_id (FK to third_party_profiles)
- service_name
- service_type
- criticality

**third_party_external_assets** (existing - no schema changes)
- id
- profile_id (FK to third_party_profiles)
- asset_type
- value
- exposure_status
- last_seen

### Architecture Tracking (NEW TABLES REQUIRED)

**third_party_architectures** (NEW - to be created)
- id
- customer_vendor_id (FK to customer_vendors)
- profile_id (FK to third_party_profiles)
- document_id (FK to documents)
- extracted_data (JSONB)
- extraction_method
- extraction_confidence
- created_at
- updated_at

**architecture_technologies** (NEW - to be created)
- id
- architecture_id (FK to third_party_architectures)
- technology
- version
- category
- source
- confidence

**architecture_services** (NEW - to be created)
- id
- architecture_id (FK to third_party_architectures)
- service_name
- service_type
- criticality
- source
- confidence

**architecture_changes** (existing - no schema changes)
- Already exists and is correctly designed
- Will be used to track changes between architecture versions

## Import Workflow Design

### 1. Manual Vendor Creation

**Input**: Form data
- customer_id
- vendor_name
- relationship_type
- business_role
- criticality
- data_sensitivity
- data_access_level
- privileged_access
- sla_penalty_risk
- regulatory_flags
- notes

**Process**:
1. Validate customer exists and user has access
2. Resolve vendor name against vendors/vendor_aliases
3. If vendor not found, create new vendor (with confirmation)
4. Create customer_vendor relationship
5. Create third_party_profile
6. Return created relationship with profile

**Output**: customer_vendor + third_party_profile

### 2. CSV/Excel Bulk Import

**Input**: CSV/Excel file with columns:
- customer
- vendor
- relationship_type
- business_role
- criticality
- data_sensitivity
- data_access_level
- privileged_access
- technology
- version
- notes
- sla_penalty_risk (optional)
- regulatory_flags (optional)

**Process**:
1. Parse file
2. Validate all rows
3. Resolve vendor names
4. Show preview with validation results
5. User confirms
6. Transaction-safe insertion
7. Create customer_vendor relationships
8. Create third_party_profiles for each
9. Return summary of created/failed rows

**Output**: Summary of created relationships

### 3. Architecture Document Import

**Input**:
- customer_id
- vendor_name
- architecture_document (file)

**Process**:
1. Validate customer and user access
2. Resolve vendor name
3. Upload document to documents table
4. Create customer_vendor relationship if not exists
5. Create third_party_profile if not exists
6. Run technology extraction (existing technology_extractor.py)
7. Create third_party_architectures record
8. Create architecture_technologies records
9. Create architecture_services records
10. Show extraction preview
11. User confirms/approves/edits
12. Update third_party_profile with confirmed technologies
13. Create third_party_profile_technologies records
14. Create third_party_profile_services records
15. Create architecture_changes if previous architecture exists
16. Optionally create architecture-change alert

**Output**: Updated profile with technologies/services

## Vendor Resolution Logic

**Priority Order**:
1. Exact canonical vendor ID match
2. Exact vendor name match (case-insensitive)
3. Alias match (case-insensitive)
4. Normalized text match (lowercase, trim, remove special chars)
5. Fuzzy match (if supported)

**Behavior**:
- If high confidence match found: use existing vendor
- If low confidence match found: ask for confirmation
- If no match found: create new vendor (with confirmation)

## Profile Creation Workflow

**Trigger Points**:
1. Manual vendor creation
2. CSV/Excel import
3. Architecture document import

**Default Profile Values**:
- business_role: from import or NULL
- description: from import or NULL
- data_access_level: from import or NULL
- privileged_access: from import or NULL
- criticality: from customer_vendor or NULL
- risk_score: calculated from customer_vendor context
- document_id: NULL (set on architecture import)

**Upsert Logic**:
- If profile exists for customer_vendor_id: update/enrich
- If profile does not exist: create new

## Technology Extraction Integration

**Existing Component**: technology_extractor.py

**Integration Points**:
1. Architecture document upload triggers extraction
2. Extraction results stored in third_party_architectures (new table)
3. Extraction results shown in preview
4. User approval moves data to third_party_profile_technologies
5. Changes tracked via architecture_changes

**Data Flow**:
```
Document Upload
    ↓
technology_extractor.py
    ↓
third_party_architectures (temporary storage)
    ↓
User Preview/Edit/Approval
    ↓
third_party_profile_technologies (committed)
    ↓
architecture_changes (if previous exists)
```

## Customer-Aware Correlation

**Existing Component**: third_party_correlation.py

**Enhancement Required**:
- Ensure correlation uses customer_vendor_id
- Ensure correlation checks third_party_profile_technologies
- Ensure correlation uses product/technology/version matching
- Ensure correlation is customer-specific

**Correlation Priority**:
1. Canonical vendor ID + customer_vendor_id match
2. Vendor alias + customer_vendor_id match
3. Product match + customer_vendor_id technology match
4. Technology match + customer_vendor_id technology match
5. Version match + customer_vendor_id technology version match
6. Architecture context + customer_vendor_id profile match
7. Existing asset context + customer_vendor_id external assets

## Match Types

**Explicit Types**:
- vendor_direct: Canonical vendor ID match
- vendor_alias: Vendor alias match
- product_match: Product name match
- technology_match: Technology name match
- version_match: Technology version match
- asset_match: External asset match
- cve_match: CVE-specific match

## Exposure Evidence Structure

```json
{
  "match": "product_match",
  "vendor": "Microsoft Corporation",
  "product": "Exchange Server",
  "customer_technology": "Exchange Server 2019",
  "customer_technology_version": "2019",
  "cve": "CVE-2026-XXXX",
  "match_confidence": 0.95,
  "evidence_sources": [
    "CVE affected products",
    "Customer profile technology"
  ]
}
```

## API Endpoints Design

### New Endpoints Required

**POST /api/third-parties/vendors/import/manual**
- Create manual vendor relationship
- Request: customer_id, vendor_name, relationship fields
- Response: created customer_vendor + profile

**POST /api/third-parties/vendors/import/csv**
- Upload CSV/Excel file
- Request: file, customer_id
- Response: preview + import confirmation

**POST /api/third-parties/vendors/import/architecture**
- Upload architecture document
- Request: customer_id, vendor_name, document
- Response: extraction preview + confirmation

**POST /api/third-parties/vendors/import/architecture/confirm**
- Confirm architecture extraction
- Request: architecture_id, approved_technologies, approved_services
- Response: updated profile + architecture_changes

### Existing Endpoints to Reuse

**GET /api/vendors** - List global vendors
**GET /api/vendors/{id}** - Get vendor details
**GET /api/third-party-profiles** - List profiles
**GET /api/third-party-profiles/{id}** - Get profile details
**POST /api/third-party-profiles** - Create profile (if exists)
**PUT /api/third-party-profiles/{id}** - Update profile

## Security Considerations

**Tenant Isolation**:
- Admin: Can select any authorized customer
- Analyst/Viewer: Can only access their own customer
- Backend must enforce independently of frontend

**Authorization Checks**:
- Every endpoint must validate customer_id
- Every endpoint must validate user role
- No frontend-only filtering

**Input Validation**:
- Validate customer exists
- Validate vendor resolves correctly
- Validate relationship fields
- Validate file types and sizes
- Reject malformed imports

## Transaction Safety

**Import Operations**:
- Use database transactions
- If any operation fails, rollback entire transaction
- Do not leave half-created records
- Return structured errors

**Example Transaction**:
```python
BEGIN
  1. Resolve vendor
  2. Create customer_vendor
  3. Create third_party_profile
  4. Create third_party_profile_technologies
  5. Create third_party_profile_services
  6. Create third_party_architectures
  7. Create architecture_changes
COMMIT
```

If any step fails: ROLLBACK

## Duplicate Protection

**Database-Level Constraints**:
- vendors: UNIQUE(name)
- vendor_aliases: UNIQUE(vendor_id, alias)
- customer_vendors: UNIQUE(customer_id, vendor_id)
- third_party_profiles: UNIQUE(customer_vendor_id)
- third_party_profile_technologies: UNIQUE(profile_id, technology, version)
- third_party_alerts: UNIQUE(customer_id, customer_vendor_id, cve_id, alert_type) WHERE cve_id IS NOT NULL

**Application-Level Checks**:
- Check for existing customer_vendor before creation
- Check for existing profile before creation
- Use upsert logic where appropriate

## Migration Plan

### Phase 2a: Create Missing Tables

**Migration**: 035_add_architecture_tables.sql
- Create third_party_architectures
- Create architecture_technologies
- Create architecture_services
- Add FK relationships

### Phase 2b: Populate Existing Profiles

**Migration**: 036_populate_existing_profiles.sql
- Create profiles for existing 4 customer_vendors
- Use default values from customer_vendors
- Ensure exposures and alerts link to profiles

### Phase 2c: Update Existing Data

**Migration**: 037_update_vendor_ids.sql
- Populate missing vendor_id in customer_vendors
- Resolve vendor text against vendors/vendor_aliases
- Report unresolved vendors

## Success Criteria for Phase 2

1. ✓ Import model designed using existing tables
2. ✓ Missing architecture tables defined
3. ✓ Profile creation workflow designed
4. ✓ Vendor resolution logic defined
5. ✓ API endpoints designed
6. ✓ Security considerations documented
7. ✓ Transaction safety defined
8. ✓ Duplicate protection defined
9. ✓ Migration plan defined

## Next Steps

Phase 3: Implement/verify backend vendor resolution
- Implement vendor resolution service
- Test vendor resolution with existing data
- Verify alias resolution
- Test fuzzy matching if supported
