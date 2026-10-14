import { ArrowRight } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { formatDate } from "@/lib/utils";
import { thirdPartyVendors } from "@/data/mock";
import { cn } from "@/lib/utils";

export function ThirdPartiesPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Third Parties</h1>
        <p className="text-sm text-muted-foreground">
          Monitor risk posture, compliance, and incident history for all
          third-party vendors in your portfolio.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
        {thirdPartyVendors.map((vendor) => {
          const riskColor =
            vendor.riskScore >= 80
              ? "text-critical"
              : vendor.riskScore >= 60
                ? "text-orange-400"
                : vendor.riskScore >= 40
                  ? "text-warning"
                  : "text-success";

          return (
            <Card key={vendor.id} className="flex flex-col">
              <CardContent className="flex flex-1 flex-col p-5">
                <div className="flex items-center gap-3">
                  <div
                    className="flex h-12 w-12 shrink-0 items-center justify-center rounded-lg text-sm font-bold text-white"
                    style={{ backgroundColor: vendor.color }}
                  >
                    {vendor.logo}
                  </div>
                  <div>
                    <h3 className="font-semibold">{vendor.name}</h3>
                    <p className="text-xs text-muted-foreground">
                      {vendor.industry}
                    </p>
                  </div>
                </div>

                <div className="mt-5 grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground">
                      Overall Risk Score
                    </p>
                    <p className={cn("text-2xl font-bold", riskColor)}>
                      {vendor.riskScore}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">
                      Active Critical CVEs
                    </p>
                    <p className="text-2xl font-bold text-critical">
                      {vendor.activeCriticalCves}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">
                      Last Incident
                    </p>
                    <p className="text-sm font-medium">
                      {formatDate(vendor.lastIncident)}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">
                      Compliance Score
                    </p>
                    <p className="text-sm font-medium">
                      {vendor.complianceScore}%
                    </p>
                  </div>
                </div>

                <div className="mt-4 flex items-center justify-between">
                  <Badge variant="secondary">
                    {vendor.monitoredCustomers} customers
                  </Badge>
                  <Button variant="outline" size="sm">
                    View Details
                    <ArrowRight className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
