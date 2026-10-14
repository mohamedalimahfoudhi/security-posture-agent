import {
  FileText,
  FileDown,
  Sheet,
  Calendar,
  BarChart3,
  Download,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { reportOptions } from "@/data/mock";

const iconMap = {
  FileText,
  FileDown,
  Sheet,
  Calendar,
  BarChart3,
};

export function ReportsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Reports</h1>
        <p className="text-sm text-muted-foreground">
          Generate executive summaries, technical reports, and compliance
          documentation.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {reportOptions.map((report) => {
          const Icon = iconMap[report.icon as keyof typeof iconMap] ?? FileText;

          return (
            <Card key={report.id} className="flex flex-col">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                    <Icon className="h-5 w-5 text-primary" />
                  </div>
                  <Badge variant="secondary">{report.format}</Badge>
                </div>
                <CardTitle className="mt-3">{report.title}</CardTitle>
                <CardDescription>{report.description}</CardDescription>
              </CardHeader>
              <CardContent className="mt-auto">
                <Button className="w-full">
                  <Download className="h-4 w-4" />
                  Generate
                </Button>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent Reports</CardTitle>
          <CardDescription>
            Previously generated reports available for download.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[
              {
                name: "Executive Summary — March 2026",
                date: "Mar 18, 2026",
                format: "PDF",
              },
              {
                name: "Weekly Threat Digest — Week 11",
                date: "Mar 15, 2026",
                format: "PDF",
              },
              {
                name: "Vendor Risk Export — Q1 2026",
                date: "Mar 10, 2026",
                format: "XLSX",
              },
            ].map((report) => (
              <div
                key={report.name}
                className="flex items-center justify-between rounded-lg border border-border p-3"
              >
                <div>
                  <p className="text-sm font-medium">{report.name}</p>
                  <p className="text-xs text-muted-foreground">{report.date}</p>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline">{report.format}</Badge>
                  <Button variant="ghost" size="sm">
                    <Download className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
