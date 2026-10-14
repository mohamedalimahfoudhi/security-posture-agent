import { Badge } from "@/components/ui/badge";
import type { AlertStatus, CustomerStatus, Severity } from "@/types";

const severityVariantMap: Record<
  Severity,
  "critical" | "high" | "medium" | "low"
> = {
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
};

const statusVariantMap: Record<
  AlertStatus,
  "open" | "investigating" | "resolved" | "closed"
> = {
  Open: "open",
  Investigating: "investigating",
  Resolved: "resolved",
  Closed: "closed",
};

const customerStatusVariantMap: Record<
  CustomerStatus,
  "atRisk" | "monitoring" | "healthy"
> = {
  "At Risk": "atRisk",
  Monitoring: "monitoring",
  Healthy: "healthy",
};

interface SeverityBadgeProps {
  severity: Severity;
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  return <Badge variant={severityVariantMap[severity]}>{severity}</Badge>;
}

interface StatusBadgeProps {
  status: AlertStatus;
}

export function StatusBadge({ status }: StatusBadgeProps) {
  return <Badge variant={statusVariantMap[status]}>{status}</Badge>;
}

interface CustomerStatusBadgeProps {
  status: CustomerStatus;
}

export function CustomerStatusBadge({ status }: CustomerStatusBadgeProps) {
  return (
    <Badge variant={customerStatusVariantMap[status]}>{status}</Badge>
  );
}

export function RiskScoreBadge({ score }: { score: number }) {
  const variant =
    score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : "low";
  return <Badge variant={variant}>{score}</Badge>;
}
