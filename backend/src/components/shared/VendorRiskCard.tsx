import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { RiskyVendor } from "@/types";

interface VendorRiskCardProps {
  vendor: RiskyVendor;
}

export function VendorRiskCard({ vendor }: VendorRiskCardProps) {
  const riskColor =
    vendor.riskScore >= 80
      ? "text-critical"
      : vendor.riskScore >= 60
        ? "text-orange-400"
        : vendor.riskScore >= 40
          ? "text-warning"
          : "text-success";

  return (
    <Card className="min-w-[200px] flex-1">
      <CardContent className="p-4">
        <div className="flex items-center gap-3">
          <div
            className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg text-xs font-bold text-white"
            style={{ backgroundColor: vendor.color }}
          >
            {vendor.logo}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold">{vendor.name}</p>
            <div className="mt-2 flex items-center gap-4">
              <div>
                <p className="text-xs text-muted-foreground">Risk Score</p>
                <p className={cn("text-lg font-bold", riskColor)}>
                  {vendor.riskScore}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Critical CVEs</p>
                <p className="text-lg font-bold text-critical">
                  {vendor.criticalCves}
                </p>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
