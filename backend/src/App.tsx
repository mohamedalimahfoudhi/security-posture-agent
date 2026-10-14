import { BrowserRouter, Routes, Route } from "react-router-dom";
import { MainLayout } from "@/components/layout/MainLayout";
import { DashboardPage } from "@/pages/DashboardPage";
import { AlertsPage } from "@/pages/AlertsPage";
import { ThreatFeedPage } from "@/pages/ThreatFeedPage";
import { ThirdPartiesPage } from "@/pages/ThirdPartiesPage";
import { CustomersPage } from "@/pages/CustomersPage";
import { AIAssistantPage } from "@/pages/AIAssistantPage";
import { ReportsPage } from "@/pages/ReportsPage";
import { SettingsPage } from "@/pages/SettingsPage";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<MainLayout />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/threat-feed" element={<ThreatFeedPage />} />
          <Route path="/third-parties" element={<ThirdPartiesPage />} />
          <Route path="/customers" element={<CustomersPage />} />
          <Route path="/ai-assistant" element={<AIAssistantPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
