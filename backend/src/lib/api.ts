import type { ThreatAlert } from "@/types";

const API_URL = "http://127.0.0.1:8000";

interface AssessmentResponse {
  id: number;
  customer: string;
  vendor: string;
  technology: string;
  vulnerability: string;
  threat_summary: string;
  severity: string;
  risk_score: number;
  exploitation_risk: string;
  recommendations: string[];
  created_at: string;
}

export async function getAssessments(): Promise<ThreatAlert[]> {
  const response = await fetch(`${API_URL}/api/assessments/`);

  if (!response.ok) {
    throw new Error("Failed to fetch assessments");
  }

  const data: AssessmentResponse[] = await response.json();

  return data.map((item) => ({
    id: String(item.id),
    severity:
      item.severity === "CRITICAL"
        ? "Critical"
        : item.severity === "HIGH"
        ? "High"
        : "Medium",
    vendor: item.vendor,
    customer: item.customer,
    threat: item.vulnerability,
    cve: "N/A",
    cvss: item.risk_score,
    date: item.created_at,
    status: "Open",
    description: item.threat_summary,
    mitreTactic: "Unknown",
    mitreTechnique: "Unknown",
    aiRecommendation: item.recommendations.join(". "),
    timeline: [],
  }));
}