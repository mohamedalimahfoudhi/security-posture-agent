import { useEffect, useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { Eye } from "lucide-react";

import { KpiCard } from "@/components/shared/KpiCard";
import { ThreatTrendChart } from "@/components/shared/ThreatTrendChart";
import { SeverityDonutChart } from "@/components/shared/SeverityDonutChart";
import { VendorRiskCard } from "@/components/shared/VendorRiskCard";
import { DataTable } from "@/components/shared/DataTable";
import { AlertDrawer } from "@/components/shared/AlertDrawer";

import {
  SeverityBadge,
  StatusBadge,
} from "@/components/shared/BadgeVariants";

import { Button } from "@/components/ui/button";
import { formatDate } from "@/lib/utils";
import { getAssessments } from "@/lib/api";

import {
  kpiMetrics,
  threatTrendData,
  severityDistribution,
  riskyVendors,
} from "@/data/mock";

import type { ThreatAlert } from "@/types";


export function DashboardPage() {

  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);


  useEffect(() => {
  console.log("✅ DashboardPage mounted");

  getAssessments()
    .then((data) => {
      console.log("✅ Assessments received:", data);
      console.log("✅ Number of assessments:", data.length);

      setAlerts(data);
    })
    .catch((error) => {
      console.error("❌ Failed to load assessments:", error);
    });

  console.log("✅ useEffect finished");
}, []);



  const columns = useMemo<ColumnDef<ThreatAlert, unknown>[]>(
    () => [

      {
        accessorKey: "severity",
        header: "Severity",
        cell: ({ row }) => (
          <SeverityBadge severity={row.original.severity} />
        ),
      },


      {
        accessorKey: "vendor",
        header: "Vendor",
        cell: ({ row }) => (
          <span className="font-medium">
            {row.original.vendor}
          </span>
        ),
      },


      {
        accessorKey: "customer",
        header: "Customer",
      },


      {
        accessorKey: "threat",
        header: "Threat",
        cell: ({ row }) => (
          <span className="max-w-[200px] truncate block">
            {row.original.threat}
          </span>
        ),
      },


      {
        accessorKey: "cvss",
        header: "CVSS",
        cell: ({ row }) => (
          <span className="font-mono font-medium">
            {row.original.cvss}
          </span>
        ),
      },


      {
        accessorKey: "date",
        header: "Date",
        cell: ({ row }) =>
          formatDate(row.original.date),
      },


      {
        accessorKey: "status",
        header: "Status",
        cell: ({ row }) => (
          <StatusBadge status={row.original.status} />
        ),
      },


      {
        id: "actions",
        header: "Action",
        cell: ({ row }) => (

          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setSelectedAlert(row.original);
              setDrawerOpen(true);
            }}
          >

            <Eye className="h-3.5 w-3.5" />

            View

          </Button>

        ),
      },

    ],
    []
  );



  return (

    <div className="space-y-6">


      <div>

        <h1 className="text-2xl font-bold tracking-tight">
          Dashboard
        </h1>


        <p className="text-sm text-muted-foreground">
          Real-time overview of third-party cybersecurity posture across your
          customer portfolio.
        </p>

      </div>



      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">

        {kpiMetrics.map((metric) => (

          <KpiCard
            key={metric.id}
            metric={metric}
          />

        ))}

      </div>




      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">

        <ThreatTrendChart
          data={threatTrendData}
        />


        <SeverityDonutChart
          data={severityDistribution}
        />

      </div>





      <div>

        <h2 className="mb-3 text-lg font-semibold">
          Top Risky Vendors
        </h2>


        <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap">

          {riskyVendors.map((vendor) => (

            <VendorRiskCard
              key={vendor.id}
              vendor={vendor}
            />

          ))}

        </div>

      </div>





      <DataTable

        title="Latest Threat Alerts"

        columns={columns}

        data={alerts}

      />





      <AlertDrawer

        alert={selectedAlert}

        open={drawerOpen}

        onOpenChange={setDrawerOpen}

      />


    </div>

  );

}