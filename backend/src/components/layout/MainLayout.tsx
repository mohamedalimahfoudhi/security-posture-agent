import { useState } from "react";
import { Outlet } from "react-router-dom";
import { Menu, X } from "lucide-react";
import { Sidebar } from "@/components/layout/Sidebar";
import { Navbar } from "@/components/layout/Navbar";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function MainLayout() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="min-h-screen bg-background">
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <div
        className={cn(
          "lg:block",
          mobileOpen ? "block" : "hidden lg:block"
        )}
      >
        <Sidebar
          collapsed={sidebarCollapsed}
          onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
          onNavigate={() => setMobileOpen(false)}
        />
      </div>

      <Navbar
        sidebarCollapsed={sidebarCollapsed}
        onMenuClick={() => setMobileOpen(!mobileOpen)}
        mobileOpen={mobileOpen}
      />

      <main
        className={cn(
          "min-h-screen pt-14 transition-all duration-200",
          sidebarCollapsed ? "lg:pl-16" : "lg:pl-60"
        )}
      >
        <div className="p-4 lg:p-6">
          <Outlet />
        </div>
      </main>

      <Button
        variant="outline"
        size="icon"
        className="fixed bottom-4 left-4 z-50 lg:hidden"
        onClick={() => setMobileOpen(!mobileOpen)}
      >
        {mobileOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
      </Button>
    </div>
  );
}
