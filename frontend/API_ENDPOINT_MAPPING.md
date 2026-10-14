# API Endpoint Mapping - Frontend Requirements

## Existing API Endpoints (from client.js)

| Endpoint | Method | Purpose | Used By |
|----------|--------|---------|---------|
| `/api/vendors/` | GET | Get customer vendors | ThirdPartiesPage |
| `/api/vendors/risk-map` | GET | Get vendor risk map | ThirdPartiesPage |
| `/api/customers/${customerId}/vendors` | GET | Get customer vendors | ThirdPartiesPage |
| `/api/customers/${customerId}/exposures` | GET | Get customer exposures | ThirdPartiesPage |
| `/api/customers/${customerId}/alerts` | GET | Get customer alerts | ThirdPartiesPage, AlertsPage |
| `/api/alerts/` | GET | Get alerts | AlertsPage |
| `/api/documents/upload` | POST | Upload document | ThirdPartiesPage |
| `/api/customers/` | GET | Get customers | App.jsx (customer selection) |
| `/api/customers/all` | GET | Get all customers | App.jsx (customer selection) |

## Backend Ecosystem Import Endpoints (from vendors.py)

| Endpoint | Method | Purpose | Status |
|----------|--------|---------|--------|
| `/api/vendors/import/ecosystem/preview` | POST | Preview ecosystem extraction | ✅ EXISTS |
| `/api/vendors/import/ecosystem/confirm` | POST | Confirm ecosystem import | ✅ EXISTS |

## Frontend Requirements vs API Coverage

### 1. Customer Selection (Admin Only)
**Requirement:** Admin can select customer, Analyst/Viewer locked to assigned customer
**Status:** ✅ ALREADY IMPLEMENTED in App.jsx
**API:** `/api/customers/`, `/api/customers/all`

### 2. Ecosystem Summary Metrics
**Requirement:** Total Vendors, Critical Vendors, High Risk Vendors, Active Exposures, Critical Alerts
**Status:** ⚠️ PARTIAL - Some metrics exist but need customer-specific aggregation
**Missing:** Need API endpoint for customer-specific ecosystem summary
**Proposed Endpoint:** `GET /api/customers/${customerId}/ecosystem-summary`

### 3. Vendor Table/Cards
**Requirement:** Vendor Name, Role, Technologies/Products, Risk Score, Risk Level, Criticality, Data Sensitivity, Active Exposures, Active Alerts, Confidence
**Status:** ⚠️ PARTIAL - `/api/customers/${customerId}/vendors` exists but may need additional fields
**Check:** Verify response includes all required fields (risk_score, confidence, exposures_count, alerts_count)

### 4. Vendor Intelligence View
**Requirement:** Vendor details, technologies, services, exposures, alerts, evidence
**Status:** ⚠️ PARTIAL - VendorDetailDrawer exists but may need updates
**API:** `/api/customers/${customerId}/vendors/${vendorId}/profile` (called in VendorDetailDrawer)
**Check:** Verify profile endpoint returns technologies, services, exposures, alerts with required fields

### 5. Import Ecosystem Workflow
**Requirement:** 5-step workflow (Select Customer → Upload → Analyze → Preview → Confirm)
**Status:** ✅ BACKEND ENDPOINTS EXIST
**API:** 
- `POST /api/vendors/import/ecosystem/preview`
- `POST /api/vendors/import/ecosystem/confirm`
**Missing:** Frontend implementation of the workflow UI

### 6. Alerts Page with Vendor/CVE Details
**Requirement:** Show Vendor, CVE ID, Affected Technology/Product, Severity, Risk, Confidence, Match Type, Status
**Status:** ⚠️ PARTIAL - AlertsPage exists but may need vendor/CVE fields
**API:** `/api/customers/${customerId}/alerts`
**Check:** Verify alerts include vendor_id, cve_id, affected_technology, match_type

### 7. Customer Dashboard with Third-Party Info
**Requirement:** Third-party vendors, vendor risk, active exposures, critical alerts, top affected vendors/technologies
**Status:** ⚠️ PARTIAL - CustomerDashboardPage exists but may need third-party metrics
**API:** `/api/customers/${customerId}/dashboard`
**Check:** Verify dashboard includes third-party ecosystem metrics

### 8. Empty/Loading/Error States
**Requirement:** Every API-driven section must have loading, empty, error states
**Status:** ⚠️ PARTIAL - Some components have loading states, need comprehensive implementation

### 9. Customer Switching
**Requirement:** Admin can switch customers, complete data reload, no data leakage
**Status:** ✅ ALREADY IMPLEMENTED in App.jsx
**API:** Uses selectedCustomerId prop throughout components

## Missing or Required Backend Endpoints

### 1. Customer Ecosystem Summary
**Purpose:** Get aggregated metrics for customer's third-party ecosystem
**Proposed Endpoint:** `GET /api/customers/${customerId}/ecosystem-summary`
**Response Schema:**
```json
{
  "total_vendors": 10,
  "critical_vendors": 3,
  "high_risk_vendors": 5,
  "active_exposures": 7,
  "critical_alerts": 2
}
```

### 2. Vendor Profile with Exposures and Alerts
**Purpose:** Get comprehensive vendor profile including exposures and alerts
**Current Endpoint:** `/api/customers/${customerId}/vendors/${vendorId}/profile`
**Check:** Verify response includes:
- technologies (with versions)
- services
- exposures (with cve_id, affected_technology, match_type, risk_score, confidence)
- alerts (with cve_id, severity, status)
- evidence

### 3. Customer Alerts with Vendor/CVE Details
**Purpose:** Get alerts with full vendor and CVE correlation details
**Current Endpoint:** `/api/customers/${customerId}/alerts`
**Check:** Verify response includes:
- vendor_id / vendor_name
- cve_id
- affected_technology
- affected_product
- match_type
- risk_score
- confidence

### 4. Customer Dashboard with Third-Party Metrics
**Purpose:** Get dashboard summary including third-party ecosystem metrics
**Current Endpoint:** `/api/customers/${customerId}/dashboard`
**Check:** Verify response includes:
- third_party_vendor_count
- third_party_risk_summary
- top_affected_vendors
- top_affected_technologies
- recent_cves_affecting_deployed

## API Client Additions Needed

Add to `frontend/src/api/client.js`:

```javascript
// Customer ecosystem summary
export const getCustomerEcosystemSummary = (customerId) =>
  get(`/api/customers/${customerId}/ecosystem-summary`, "Failed to fetch ecosystem summary");

// Ecosystem import preview
export const previewEcosystemImport = (documentId, customerId) => {
  const body = { document_id: documentId };
  if (customerId) body.customer_id = customerId;
  return apiFetch("/api/vendors/import/ecosystem/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  }).then(r => {
    if (!r.ok) throw new Error("Failed to preview ecosystem import");
    return r.json();
  });
};

// Ecosystem import confirm
export const confirmEcosystemImport = (documentId, customerId, acceptedEntities, rejectedEntities, editedEntities) => {
  const body = { document_id: documentId, accepted_entities: acceptedEntities, rejected_entities: rejectedEntities };
  if (customerId) body.customer_id = customerId;
  if (editedEntities) body.edited_entities = editedEntities;
  return apiFetch("/api/vendors/import/ecosystem/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  }).then(r => {
    if (!r.ok) throw new Error("Failed to confirm ecosystem import");
    return r.json();
  });
};
```

## Next Steps

1. ✅ Explore existing frontend structure - COMPLETE
2. 🔄 Map existing API endpoints to frontend requirements - IN PROGRESS
3. ⏳ Implement Third Parties Page with customer selection
4. ⏳ Implement Ecosystem Summary metrics
5. ⏳ Implement Vendor Table/Cards with risk/confidence
6. ⏳ Implement Vendor Intelligence View
7. ⏳ Implement Import Ecosystem workflow (5 steps)
8. ⏳ Update Alerts Page with vendor/CVE details
9. ⏳ Update Customer Dashboard with third-party info
10. ⏳ Implement empty/loading/error states
11. ⏳ Implement customer switching (admin only)
12. ⏳ Test end-to-end with ACME Corporation customer
