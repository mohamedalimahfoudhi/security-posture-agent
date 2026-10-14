import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/shared/DataTable";
import {
  CustomerStatusBadge,
  RiskScoreBadge,
} from "@/components/shared/BadgeVariants";
import { customers } from "@/data/mock";
import type { Customer } from "@/types";

export function CustomersPage() {
  const columns = useMemo<ColumnDef<Customer, unknown>[]>(
    () => [
      {
        accessorKey: "name",
        header: "Customer",
        cell: ({ row }) => (
          <span className="font-medium">{row.original.name}</span>
        ),
      },
      {
        accessorKey: "industry",
        header: "Industry",
      },
      {
        accessorKey: "country",
        header: "Country",
      },
      {
        accessorKey: "monitoredVendors",
        header: "Monitored Vendors",
        cell: ({ row }) => row.original.monitoredVendors,
      },
      {
        accessorKey: "riskScore",
        header: "Risk Score",
        cell: ({ row }) => <RiskScoreBadge score={row.original.riskScore} />,
      },
      {
        accessorKey: "openAlerts",
        header: "Open Alerts",
        cell: ({ row }) => (
          <span
            className={
              row.original.openAlerts > 5
                ? "font-medium text-critical"
                : undefined
            }
          >
            {row.original.openAlerts}
          </span>
        ),
      },
      {
        accessorKey: "status",
        header: "Status",
        cell: ({ row }) => (
          <CustomerStatusBadge status={row.original.status} />
        ),
      },
    ],
    []
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Customers</h1>
        <p className="text-sm text-muted-foreground">
          Customer portfolio overview with third-party risk exposure and alert
          status.
        </p>
      </div>

      <DataTable columns={columns} data={customers} />
    </div>
  );
}
