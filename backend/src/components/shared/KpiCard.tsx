import {
  AlertTriangle,
  Building2,
  ShieldAlert,
  TrendingDown,
  TrendingUp,
  Users,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { KpiMetric } from "@/types";

const iconMap = {
  AlertTriangle,
  ShieldAlert,
  Building2,
  Users,
};

interface KpiCardProps {
  metric: KpiMetric;
}

export function KpiCard({ metric }: KpiCardProps) {
  const Icon = iconMap[metric.icon as keyof typeof iconMap] ?? AlertTriangle;
  const isPositive = metric.trend >= 0;
  const TrendIcon = isPositive ? TrendingUp : TrendingDown;
  const isPercent = metric.trendFormat !== "number";

  return (
    <Card>
      <CardContent className="p-5">
        <div className="flex items-start justify-between">
          <div className="space-y-3">
            <p className="text-sm font-medium text-muted-foreground">
              {metric.label}
            </p>
            <p className="text-3xl font-bold tracking-tight">
              {metric.value.toLocaleString()}
            </p>
            <p className="text-xs text-muted-foreground">{metric.description}</p>
            <div className="flex items-center gap-1.5">
              <TrendIcon
                className={cn(
                  "h-3.5 w-3.5",
                  isPositive ? "text-critical" : "text-success"
                )}
              />
              <span
                className={cn(
                  "text-xs font-medium",
                  isPositive ? "text-critical" : "text-success"
                )}
              >
                {isPositive ? "+" : ""}
                {metric.trend}
                {isPercent ? "%" : ""}
              </span>
              <span className="text-xs text-muted-foreground">
                {metric.trendLabel}
              </span>
            </div>
          </div>
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
            <Icon className="h-5 w-5 text-primary" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
