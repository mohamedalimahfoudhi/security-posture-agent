// TypeScript interfaces for backend API responses

export interface Asset {
  id: number;
  customer_id: number;
  document_id: number;
  technology: string;
  vendor: string | null;
  version: string | null;
  criticality: string;
  internet_exposed: boolean;
  sensitive_data: boolean;
  category: string | null;
  operating_system: string | null;
  database: string | null;
  cloud_provider: string | null;
  web_server: string | null;
  firewall: string | null;
  virtualization: string | null;
  programming_language: string | null;
  framework: string | null;
  security_tools: string | null;
  network_devices: string | null;
  confidence: number;
  created_at: string;
  updated_at: string;
  source_document: string | null;
}

export interface AssetsResponse {
  assets: Asset[];
  total: number;
  limit: number;
  offset: number;
}

export interface AssetInventory {
  technologies: TechnologySummary[];
  category_breakdown: CategoryBreakdown[];
  criticality_breakdown: CriticalityBreakdown[];
  total_technologies: number;
  total_assets: number;
}

export interface TechnologySummary {
  technology: string;
  vendor: string | null;
  count: number;
  latest_version: string | null;
  max_criticality: string;
}

export interface CategoryBreakdown {
  category: string;
  count: number;
}

export interface CriticalityBreakdown {
  criticality: string;
  count: number;
}

export interface DetectedTechnology {
  technology: string;
  vendor: string | null;
  version: string | null;
  criticality: string;
}

export interface DetectedTechnologiesResponse {
  technologies: DetectedTechnology[];
  total_count: number;
}

export interface Document {
  id: number;
  customer_id: number;
  filename: string;
  file_type: string;
  file_size: number;
  upload_status: string;
  extraction_status: string;
  uploaded_at: string;
  processed_at: string | null;
  error_message: string | null;
}

export interface DocumentUploadResponse {
  id: number;
  filename: string;
  file_type: string;
  file_size: number;
  upload_status: string;
  message: string;
}

export interface ExtractionResponse {
  document_id: number;
  assets_extracted: number;
  message: string;
}

export interface DashboardSummary {
  critical_threats: number;
  high_threats: number;
  total_assessments: number;
  average_risk_score: number;
}

export interface Assessment {
  id: number;
  customer_id: number;
  vendor_id: number | null;
  cve_id: string | null;
  severity: string;
  risk_score: number;
  confidence: number;
  evidence: string | null;
  created_at: string;
  updated_at: string;
}

export interface SeverityTrend {
  time: string;
  critical: number;
  high: number;
  elevated: number;
  low: number;
}

export interface VendorRiskMap {
  nodes: VendorNode[];
  links: VendorLink[];
}

export interface VendorNode {
  id: string;
  name: string;
  severity: string;
  risk_score: number;
}

export interface VendorLink {
  source: string;
  target: string;
  severity: string;
}
