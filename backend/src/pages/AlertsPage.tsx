import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { Eye } from "lucide-react";
import { DataTable } from "@/components/shared/DataTable";
import { AlertDrawer } from "@/components/shared/AlertDrawer";
import {
  SeverityBadge,
  StatusBadge,
} from "@/components/shared/BadgeVariants";
import { Button } from "@/components/ui/button";
import { formatDate } from "@/lib/utils";
import { threatAlerts } from "@/data/mock";
import type { ThreatAlert } from "@/types";

export function AlertsPage() {
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const columns = useMemo<ColumnDef<ThreatAlert, unknown>[]>(
    () => [
      {
        accessorKey: "severity",
        header: "Severity",
        cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
      },
      {
        accessorKey: "vendor",
        header: "Vendor",
        cell: ({ row }) => (
          <span className="font-medium">{row.original.vendor}</span>
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
          <span className="max-w-[240px] truncate block">
            {row.original.threat}
          </span>
        ),
      },
      {
        accessorKey: "cve",
        header: "CVE",
        cell: ({ row }) => (
          <span className="font-mono text-xs">{row.original.cve}</span>
        ),
      },
      {
        accessorKey: "cvss",
        header: "CVSS",
        cell: ({ row }) => (
          <span className="font-mono font-medium">{row.original.cvss}</span>
        ),
      },
      {
        accessorKey: "date",
        header: "Date",
        cell: ({ row }) => formatDate(row.original.date),
      },
      {
        accessorKey: "status",
        header: "Status",
        cell: ({ row }) => <StatusBadge status={row.original.status} />,
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
        <h1 className="text-2xl font-bold tracking-tight">Alerts</h1>
        <p className="text-sm text-muted-foreground">
          All active and historical threat alerts across monitored third-party
          vendors and customers.
        </p>
      </div>

      <DataTable columns={columns} data={threatAlerts} />

      <AlertDrawer
        alert={selectedAlert}
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
      />
    </div>
  );
}
