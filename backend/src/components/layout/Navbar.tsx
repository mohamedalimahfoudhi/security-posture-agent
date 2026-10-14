import { Bell, Moon, Shield, Menu } from "lucide-react";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { SearchBar } from "@/components/shared/SearchBar";
import { cn } from "@/lib/utils";

interface NavbarProps {
  sidebarCollapsed: boolean;
  onMenuClick?: () => void;
  mobileOpen?: boolean;
}

export function Navbar({
  sidebarCollapsed,
  onMenuClick,
}: NavbarProps) {
  return (
    <header
      className={cn(
        "fixed right-0 top-0 z-30 flex h-14 items-center justify-between border-b border-border bg-card px-4 transition-all duration-200 lg:px-6",
        sidebarCollapsed ? "lg:left-16" : "lg:left-60",
        "left-0"
      )}
    >
      <div className="flex items-center gap-3">
        <Button
          variant="ghost"
          size="icon"
          className="lg:hidden"
          onClick={onMenuClick}
        >
          <Menu className="h-4 w-4" />
        </Button>
        <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
          <Shield className="h-4 w-4 text-white" />
        </div>
        <div className="hidden sm:block">
          <p className="text-sm font-semibold leading-tight">
            Third-Party Cybersecurity Posture Agent
          </p>
          <p className="hidden text-xs text-muted-foreground md:block">
            SOC Command Center
          </p>
        </div>
      </div>

      <div className="hidden flex-1 justify-center px-6 lg:flex">
        <SearchBar className="max-w-md w-full" />
      </div>

      <div className="flex items-center gap-2 sm:gap-3">
        <SearchBar className="w-36 sm:w-48 lg:hidden" placeholder="Search..." />

        <Button variant="ghost" size="icon" className="relative">
          <Bell className="h-4 w-4" />
          <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-critical" />
        </Button>

        <div className="hidden items-center gap-2 sm:flex">
          <Moon className="h-4 w-4 text-muted-foreground" />
          <Switch defaultChecked aria-label="Dark mode" />
        </div>

        <Avatar>
          <AvatarFallback>SA</AvatarFallback>
        </Avatar>
      </div>
    </header>
  );
}
