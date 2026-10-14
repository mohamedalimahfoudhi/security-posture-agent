export type Severity = "Critical" | "High" | "Medium" | "Low";
export type AlertStatus = "Open" | "Investigating" | "Resolved" | "Closed";
export type CustomerStatus = "At Risk" | "Monitoring" | "Healthy";

export interface KpiMetric {
  id: string;
  label: string;
  value: number;
  description: string;
  trend: number;
  trendLabel: string;
  trendFormat?: "percent" | "number";
  icon: string;
}

export interface ThreatTrendPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface SeverityDistribution {
  name: Severity;
  value: number;
  color: string;
}

export interface RiskyVendor {
  id: string;
  name: string;
  riskScore: number;
  criticalCves: number;
  logo: string;
  color: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  title: string;
  description: string;
}

export interface ThreatAlert {
  id: string;
  severity: Severity;
  vendor: string;
  customer: string;
  threat: string;
  cve: string;
  cvss: number;
  date: string;
  status: AlertStatus;
  description: string;
  mitreTactic: string;
  mitreTechnique: string;
  aiRecommendation: string;
  timeline: TimelineEvent[];
}

export interface ThirdPartyVendor {
  id: string;
  name: string;
  logo: string;
  color: string;
  riskScore: number;
  activeCriticalCves: number;
  lastIncident: string;
  complianceScore: number;
  industry: string;
  monitoredCustomers: number;
}

export interface Customer {
  id: string;
  name: string;
  industry: string;
  country: string;
  monitoredVendors: number;
  riskScore: number;
  openAlerts: number;
  status: CustomerStatus;
}

export interface ThreatFeedItem {
  id: string;
  title: string;
  vendor: string;
  severity: Severity;
  published: string;
  summary: string;
  fullContent: string;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: string;
}

export interface ChatConversation {
  id: string;
  title: string;
  messages: ChatMessage[];
  updatedAt: string;
}

export interface ReportOption {
  id: string;
  title: string;
  description: string;
  icon: string;
  format: string;
}

export interface SettingsSection {
  id: string;
  title: string;
  description: string;
  icon: string;
}

export interface NavItem {
  id: string;
  label: string;
  path: string;
  icon: string;
}
