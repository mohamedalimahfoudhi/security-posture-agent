import {
  Settings,
  Bell,
  Bot,
  Palette,
  Plug,
  Key,
  ChevronRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { settingsSections } from "@/data/mock";

const iconMap = {
  Settings,
  Bell,
  Bot,
  Palette,
  Plug,
  Key,
};

export function SettingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">
          Configure platform preferences, notifications, and integrations.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {settingsSections.map((section) => {
          const Icon = iconMap[section.icon as keyof typeof iconMap] ?? Settings;

          return (
            <Card
              key={section.id}
              className="cursor-pointer transition-colors hover:border-primary/30"
            >
              <CardContent className="flex items-center gap-4 p-5">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                  <Icon className="h-5 w-5 text-primary" />
                </div>
                <div className="min-w-0 flex-1">
                  <h3 className="font-semibold">{section.title}</h3>
                  <p className="text-xs text-muted-foreground">
                    {section.description}
                  </p>
                </div>
                <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
              </CardContent>
            </Card>
          );
        })}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Quick Settings</CardTitle>
          <CardDescription>
            Commonly adjusted platform settings.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {[
            {
              label: "Email notifications for critical alerts",
              description: "Receive immediate email for CVSS 9.0+ threats",
              defaultChecked: true,
            },
            {
              label: "Auto-assign alerts to available analysts",
              description: "Round-robin assignment for new critical alerts",
              defaultChecked: false,
            },
            {
              label: "Enable AI-powered threat correlation",
              description: "Use AI to correlate vendor advisories with assets",
              defaultChecked: true,
            },
            {
              label: "Weekly executive digest",
              description: "Automated weekly report to leadership",
              defaultChecked: true,
            },
          ].map((setting) => (
            <div
              key={setting.label}
              className="flex items-center justify-between rounded-lg border border-border p-4"
            >
              <div>
                <p className="text-sm font-medium">{setting.label}</p>
                <p className="text-xs text-muted-foreground">
                  {setting.description}
                </p>
              </div>
              <Switch defaultChecked={setting.defaultChecked} />
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
