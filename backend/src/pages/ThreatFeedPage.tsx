import { useState } from "react";
import { ExternalLink } from "lucide-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/shared/BadgeVariants";
import { formatDateTime } from "@/lib/utils";
import { threatFeedItems } from "@/data/mock";

export function ThreatFeedPage() {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Threat Feed</h1>
        <p className="text-sm text-muted-foreground">
          Real-time threat intelligence from vendor advisories, CVE databases,
          and security research feeds.
        </p>
      </div>

      <div className="space-y-4">
        {threatFeedItems.map((item) => (
          <Card key={item.id}>
            <CardHeader className="pb-3">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={item.severity} />
                    <span className="text-xs text-muted-foreground">
                      {item.vendor}
                    </span>
                  </div>
                  <h3 className="text-base font-semibold leading-snug">
                    {item.title}
                  </h3>
                </div>
                <span className="shrink-0 text-xs text-muted-foreground">
                  {formatDateTime(item.published)}
                </span>
              </div>
            </CardHeader>
            <CardContent>
              <p className="text-sm leading-relaxed text-muted-foreground">
                {expandedId === item.id ? item.fullContent : item.summary}
              </p>
              <Button
                variant="link"
                size="sm"
                className="mt-3 h-auto p-0"
                onClick={() =>
                  setExpandedId(expandedId === item.id ? null : item.id)
                }
              >
                <ExternalLink className="h-3.5 w-3.5" />
                {expandedId === item.id ? "Show Less" : "Read More"}
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
