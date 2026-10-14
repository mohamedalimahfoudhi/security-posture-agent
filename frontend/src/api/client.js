export const API_URL = "http://localhost:8000";

export async function apiFetch(path, options = {}) {
  const token = localStorage.getItem("access_token");
  const headers = new Headers(options.headers || {});
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const response = await fetch(`${API_URL}${path}`, { ...options, headers });
  if (response.status === 401) {
    localStorage.removeItem("access_token");
    window.dispatchEvent(new Event("auth:expired"));
  }
  return response;
}

async function get(path, message) {
  const response = await apiFetch(path);
  console.log('[client.js] GET', path, 'Status:', response.status);
  if (!response.ok) {
    console.error('[client.js] GET failed:', path, response.status, response.statusText);
    throw new Error(message);
  }
  const data = await response.json();
  console.log('[client.js] GET response data:', data);
  return data;
}

export const getDashboardSummary = () => get("/api/dashboard/summary", "Failed to fetch dashboard data");
export const getAssessments = () => get("/api/assessments/", "Failed to fetch assessments");
export const getSeverityTrend = () => get("/api/assessments/severity-trend", "Failed to fetch severity trend");
export const getVendorRiskMap = () => get("/api/vendors/risk-map", "Failed to fetch vendor risk map");
export const getDocuments = () => get("/api/documents/", "Failed to fetch documents");
export const getDocument = (documentId) => get(`/api/documents/${documentId}`, "Failed to fetch document");
export const deleteDocument = (documentId) => apiFetch(`/api/documents/${documentId}`, { method: "DELETE" }).then(r => {
  if (!r.ok) throw new Error("Failed to delete document");
  return r.json();
});
export const getAssets = (customerId, limit = 200, offset = 0) => {
  // The customer-scoped endpoint lives under /api/assets/customers/{id}/assets
  // (because assets.py router has prefix /api/assets)
  if (customerId) {
    return get(`/api/assets/customers/${customerId}/assets?limit=${limit}&offset=${offset}`, "Failed to fetch assets");
  }
  return get(`/api/assets/?limit=${limit}&offset=${offset}`, "Failed to fetch assets");
};

export const getAssetInventory = () => get("/api/assets/inventory", "Failed to fetch asset inventory");
export const getDetectedTechnologies = () => get("/api/assets/detected-technologies", "Failed to fetch detected technologies");
export const getAsset = (assetId) => get(`/api/assets/${assetId}`, "Failed to fetch asset");
export const getAlerts = () => get("/api/alerts/", "Failed to fetch alerts");
export const getAlertDetail = (alertId) => get(`/api/alerts/${alertId}`, "Failed to fetch alert detail");
export const getAlertNotifications = (alertId) => get(`/api/alerts/${alertId}/notifications`, "Failed to fetch alert notifications");
export const updateAlertStatus = (alertId, status) => apiFetch(`/api/alerts/${alertId}/status`, {
  method: "PATCH",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ status })
}).then(r => {
  if (!r.ok) throw new Error("Failed to update alert status");
  return r.json();
});
export const getCves = () => get("/api/cves/", "Failed to fetch CVEs");
export const getCustomers = () => get("/api/customers/", "Failed to fetch customers");
export const getAllCustomers = () => get("/api/customers/all", "Failed to fetch all customers");

export const createCustomer = async (data) => {
  const response = await apiFetch("/api/customers/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || "Failed to create customer");
  }
  return response.json();
};

export const updateCustomer = async (id, data) => {
  const response = await apiFetch(`/api/customers/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || "Failed to update customer");
  }
  return response.json();
};

export const deleteCustomer = async (id) => {
  const response = await apiFetch(`/api/customers/${id}`, {
    method: "DELETE"
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || "Failed to delete customer");
  }
  return true;
};

export const getUsers = () => get("/api/users", "Failed to fetch users");

// Customer-centric dashboard helpers
export const getCustomerDashboard = (customerId) =>
  get(`/api/customers/${customerId}/dashboard`, "Failed to fetch customer dashboard");

export const getCustomerAlerts = (customerId, filters = {}) => {
  const params = new URLSearchParams();
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.alert_type) params.set("alert_type", filters.alert_type);
  if (filters.status) params.set("status", filters.status);
  if (filters.vendor) params.set("vendor", filters.vendor);
  if (filters.limit) params.set("limit", filters.limit);
  if (filters.offset) params.set("offset", filters.offset);
  const qs = params.toString();
  return get(`/api/customers/${customerId}/alerts${qs ? `?${qs}` : ""}`, "Failed to fetch customer alerts");
};

export const getCustomerVendors = (customerId) =>
  get(`/api/customers/${customerId}/vendors`, "Failed to fetch customer vendors");

export const getCustomerExposures = (customerId, limit = 50, offset = 0) =>
  get(`/api/customers/${customerId}/exposures?limit=${limit}&offset=${offset}`, "Failed to fetch customer exposures");

export async function updateUser(userId, updates) {
  const response = await apiFetch(`/api/users/${userId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(updates),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || "Failed to update user");
  }
  return response.json();
}

export async function changePassword(currentPassword, newPassword) {
  const response = await apiFetch("/api/auth/change-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || "Failed to change password");
  }
  return response.json();
}

export async function analyzeWithAI(data) {
  const response = await apiFetch("/ai/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
  if (!response.ok) throw new Error("Failed to analyze with AI");
  return response.json();
}

export async function uploadDocument(file) {
  const formData = new FormData();
  formData.append("file", file);
  const response = await apiFetch("/api/documents/upload", { method: "POST", body: formData });
  if (!response.ok) throw new Error("Failed to upload document");
  return response.json();
}

export async function extractTechnologies(documentId) {
  const response = await apiFetch(`/api/documents/extract/${documentId}`, { method: "POST" });
  if (!response.ok) throw new Error("Failed to extract technologies");
  return response.json();
}

export async function deleteAsset(assetId) {
  const response = await apiFetch(`/api/assets/${assetId}`, { method: "DELETE" });
  if (!response.ok) throw new Error("Failed to delete asset");
  return response.json();
}

export async function previewEcosystemImport(documentId) {
  const response = await apiFetch(`/api/vendors/import/ecosystem/preview?document_id=${documentId}`, { method: "GET" });
  if (!response.ok) throw new Error("Failed to preview ecosystem import");
  return response.json();
}

export async function confirmEcosystemImport(data) {
  const response = await apiFetch("/api/vendors/import/ecosystem/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || "Failed to confirm ecosystem import");
  }
  return response.json();
}

export async function assessApplicability(_customerId, vulnerabilityTitle, assets) {
  const response = await apiFetch("/api/applicability/assess", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ vulnerability_title: vulnerabilityTitle, assets }) });
  if (!response.ok) throw new Error("Failed to assess applicability");
  return response.json();
}

function buildUrl(path, params = {}) {
  const url = new URL(path, API_URL);
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      url.searchParams.set(key, value);
    }
  });
  return `${url.pathname}${url.search}`;
}

export async function chatWithAI(message, conversation_id, selected_customer_id = null) {
  const body = { message };
  if (conversation_id) {
    body.conversation_id = conversation_id;
  }
  // Pass selected_customer_id when present (Admin context switching).
  // Backend enforces authorization — we simply forward the value.
  if (selected_customer_id != null) {
    body.selected_customer_id = selected_customer_id;
  }

  const response = await apiFetch("/api/ai/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error("Failed to chat with AI");
  return response.json();
}

export async function getChatConversations() {
  const response = await apiFetch("/api/ai/conversations");
  if (!response.ok) throw new Error("Failed to load AI chat conversations");
  return response.json();
}

export async function getChatHistory(conversationId) {
  const response = await apiFetch(buildUrl("/api/ai/history", { conversation_id: conversationId }));
  if (!response.ok) throw new Error("Failed to load AI chat history");
  return response.json();
}

export async function clearChatHistory(conversationId) {
  const response = await apiFetch(buildUrl("/api/ai/history", { conversation_id: conversationId }), { method: "DELETE" });
  if (!response.ok) throw new Error("Failed to clear AI chat history");
  return response.json();
}

export const getNotificationRecipients = () => get("/api/notifications/recipients", "Failed to fetch notification recipients");
export const createNotificationRecipient = (recipient) => apiFetch("/api/notifications/recipients", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(recipient),
}).then(r => {
  if (!r.ok) throw new Error("Failed to create notification recipient");
  return r.json();
});
export const deleteNotificationRecipient = (recipientId) => apiFetch(`/api/notifications/recipients/${recipientId}`, { method: "DELETE" }).then(r => {
  if (!r.ok) throw new Error("Failed to delete notification recipient");
  return r.json();
});
export const getNotificationDrafts = () => get("/api/notifications/drafts", "Failed to fetch notification drafts");
export const getNotificationDraft = (draftId) => get(`/api/notifications/drafts/${draftId}`, "Failed to fetch notification draft");
export const sendNotificationDraft = (draftId) => apiFetch(`/api/notifications/drafts/${draftId}/send`, { method: "POST" }).then(r => {
  if (!r.ok) throw new Error("Failed to send notification draft");
  return r.json();
});

// Intelligence dashboard
export const getIntelligenceDashboard = () => get("/api/reports/intelligence-dashboard", "Failed to fetch intelligence dashboard data");

// Weekly digest
export const getWeeklyDigest = () => get("/api/reports/third-party-weekly", "Failed to fetch weekly digest");
export const regenerateWeeklyDigest = () => apiFetch("/api/reports/third-party-weekly/regenerate", { method: "POST" }).then(r => {
  if (!r.ok) throw new Error("Failed to regenerate weekly digest");
  return r.json();
});

// Data Breaches — customer-specific breach correlation
export const getDataBreaches = (customerId) => get(`/api/reports/customers/${customerId}/data-breaches`, "Failed to fetch data breaches");
export const getDataBreachDetail = (customerId, breachId) => get(`/api/reports/customers/${customerId}/data-breaches/${breachId}`, "Failed to fetch data breach detail");
