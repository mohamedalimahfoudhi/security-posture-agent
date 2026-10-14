import type { ReactNode } from "react";
import {
  UserPlus,
  XCircle,
  FileText,
  Clock,
  Shield,
  Target,
  Bot,
} from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { SeverityBadge } from "@/components/shared/BadgeVariants";
import { formatDateTime } from "@/lib/utils";
import type { ThreatAlert } from "@/types";

interface AlertDrawerProps {
  alert: ThreatAlert | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function DetailRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between">
      <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      <span className="text-sm text-foreground sm:text-right">{value}</span>
    </div>
  );
}

export function AlertDrawer({ alert, open, onOpenChange }: AlertDrawerProps) {
  if (!alert) return null;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
        <SheetHeader className="pr-8">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={alert.severity} />
          </div>
          <SheetTitle className="text-xl">{alert.threat}</SheetTitle>
          <SheetDescription>{alert.cve}</SheetDescription>
        </SheetHeader>

        <div className="mt-6 space-y-6">
          <div className="space-y-3 rounded-lg border border-border bg-background p-4">
            <DetailRow label="CVSS Score" value={<span className="font-bold text-critical">{alert.cvss}</span>} />
            <DetailRow label="Affected Vendor" value={alert.vendor} />
            <DetailRow label="Affected Customer" value={alert.customer} />
            <DetailRow label="Detection Date" value={formatDateTime(alert.date)} />
          </div>

          <div>
            <h4 className="mb-2 text-sm font-semibold">Description</h4>
            <p className="text-sm leading-relaxed text-muted-foreground">
              {alert.description}
            </p>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="rounded-lg border border-border p-3">
              <div className="mb-1 flex items-center gap-2">
                <Target className="h-4 w-4 text-primary" />
                <span className="text-xs font-medium uppercase text-muted-foreground">
                  MITRE Tactic
                </span>
              </div>
              <p className="text-sm font-medium">{alert.mitreTactic}</p>
            </div>
            <div className="rounded-lg border border-border p-3">
              <div className="mb-1 flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary" />
                <span className="text-xs font-medium uppercase text-muted-foreground">
                  MITRE Technique
                </span>
              </div>
              <p className="text-sm font-medium">{alert.mitreTechnique}</p>
            </div>
          </div>

          <div className="rounded-lg border border-primary/30 bg-primary/5 p-4">
            <div className="mb-2 flex items-center gap-2">
              <Bot className="h-4 w-4 text-primary" />
              <h4 className="text-sm font-semibold">AI Recommendation</h4>
            </div>
            <p className="text-sm leading-relaxed text-muted-foreground">
              {alert.aiRecommendation}
            </p>
          </div>

          <div>
            <div className="mb-3 flex items-center gap-2">
              <Clock className="h-4 w-4 text-muted-foreground" />
              <h4 className="text-sm font-semibold">Timeline</h4>
            </div>
            <div className="space-y-4 border-l-2 border-border pl-4">
              {alert.timeline.map((event) => (
                <div key={event.id} className="relative">
                  <div className="absolute -left-[21px] top-1.5 h-2.5 w-2.5 rounded-full border-2 border-primary bg-card" />
                  <p className="text-xs text-muted-foreground">
                    {formatDateTime(event.timestamp)}
                  </p>
                  <p className="text-sm font-medium">{event.title}</p>
                  <p className="text-xs text-muted-foreground">
                    {event.description}
                  </p>
                </div>
              ))}
            </div>
          </div>

          <Separator />

          <div className="flex flex-wrap gap-2 pb-4">
            <Button size="sm">
              <UserPlus className="h-4 w-4" />
              Assign
            </Button>
            <Button size="sm" variant="outline">
              <XCircle className="h-4 w-4" />
              Close Alert
            </Button>
            <Button size="sm" variant="secondary">
              <FileText className="h-4 w-4" />
              Generate Report
            </Button>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
