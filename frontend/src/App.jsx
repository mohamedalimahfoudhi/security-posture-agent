import { useState, useEffect } from "react";

import Sidebar from "./components/Sidebar";
import StatusStrip from "./components/StatusStrip";
import SeverityTrend from "./components/SeverityTrend";
import LiveFindingsFeed from "./components/LiveFindingsFeed";
import AIAssistant from "./components/AIAssistant";
import CustomerDashboardPage from "./components/CustomerDashboardPage";
import TechnologyInventory from "./components/TechnologyInventory";
import DetectedTechnologies from "./components/DetectedTechnologies";
import ThirdPartiesPage from "./components/ThirdPartiesPage";
import AlertsPage from "./components/AlertsPage";
import ThreatFeedPage from "./components/ThreatFeedPage";
import CustomersPage from "./components/CustomersPage";
import ReportsPage from "./components/ReportsPage";
import SettingsPage from "./components/SettingsPage";
import WeeklyDigestPage from "./components/WeeklyDigestPage";
import NotificationBell from "./components/NotificationBell";
import DataBreachesPage from "./components/DataBreachesPage";
import Panel from "./components/ui/Panel";
import MetricBlock from "./components/ui/MetricBlock";
import SectionHeader from "./components/ui/SectionHeader";
import SeverityBadge from "./components/ui/SeverityBadge";
import RiskIndicator from "./components/ui/RiskIndicator";
import StatusBadge from "./components/ui/StatusBadge";
import EmptyState from "./components/ui/EmptyState";

import RiskMatrix from "./components/cti/RiskMatrix";
import IntelligenceTimeline from "./components/cti/IntelligenceTimeline";
import SeverityDistribution from "./components/cti/SeverityDistribution";
import VendorInvestigationDrawer from "./components/cti/VendorInvestigationDrawer";
import BreachInvestigationDrawer from "./components/cti/BreachInvestigationDrawer";

import { getDashboardSummary, getDetectedTechnologies, getCustomerDashboard, getDataBreaches } from "./api/client";
import ProtectedRoute from "./auth/ProtectedRoute";
import { useAuth } from "./auth/AuthContext";

function App() {
  const { user, logout } = useAuth();
  const [activeNav, setActiveNav] = useState("dashboard");
  const [selectedCustomerId, setSelectedCustomerId] = useState(null);

  useEffect(() => {
    if (user?.customer_id && selectedCustomerId === null) {
      setSelectedCustomerId(user.customer_id);
    }
  }, [user]);

  const handleCustomerChange = (customerId) => {
    setSelectedCustomerId(customerId);
  };

  const [stats, setStats] = useState({
    total_assessments: 0,
    critical_threats: 0,
    high_threats: 0,
    average_risk_score: 0
  });

  const [techCount, setTechCount] = useState(0);

  useEffect(() => {
    async function loadDashboard() {
      try {
        const data = await getDashboardSummary();
        setStats(data);
      } catch(error) {
        if (error.message.includes('401') || error.message.includes('authenticated')) {
          localStorage.removeItem("access_token");
          window.dispatchEvent(new Event("auth:expired"));
        }
      }
    }
    loadDashboard();
    const handleDataRefresh = () => loadDashboard();
    window.addEventListener("data:refresh", handleDataRefresh);
    return () => window.removeEventListener("data:refresh", handleDataRefresh);
  }, []);

  useEffect(() => {
    async function loadTechCount() {
      try {
        const data = await getDetectedTechnologies();
        setTechCount(data.total_count || 0);
      } catch (error) {
        console.error('Failed to load technology count:', error);
      }
    }
    loadTechCount();
    const handleDataRefresh = () => loadTechCount();
    window.addEventListener("data:refresh", handleDataRefresh);
    return () => window.removeEventListener("data:refresh", handleDataRefresh);
  }, []);

  return (
    <ProtectedRoute>
      <div className="flex h-screen bg-void overflow-hidden">
        <Sidebar
          activeNav={activeNav}
          onNavChange={setActiveNav}
          role={user?.role}
          selectedCustomerId={selectedCustomerId}
          onCustomerChange={handleCustomerChange}
        />

        <div className="flex-1 flex flex-col overflow-hidden">
          <header className="h-16 bg-panel border-b border-hairline flex items-center px-6 shadow-sm">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-ember-bright rounded-lg flex items-center justify-center">
                <span className="text-white font-bold text-sm">N</span>
              </div>
              <div>
                <h1 className="text-xl font-semibold font-display text-ink">
                  AI-TIP
                </h1>
                <p className="text-xs text-mist font-body">Threat Intelligence Platform</p>
              </div>
            </div>

            <div className="ml-auto flex items-center gap-4 text-sm text-mist">
              <NotificationBell onViewAll={() => setActiveNav('alerts')} />
              <span className="text-ink font-medium">{user?.full_name || user?.username}</span>
              <button 
                onClick={logout} 
                className="px-3 py-1.5 text-ember-bright border border-ember-bright rounded hover:bg-ember-bright hover:text-white transition-colors font-body text-xs font-medium"
              >
                Logout
              </button>
            </div>
          </header>

          <main className="flex-1 overflow-auto p-6 custom-scrollbar relative">
            {activeNav === 'dashboard' && (
              <CustomerDashboardPage customerId={selectedCustomerId} />
            )}

            {activeNav === 'alerts' && <AlertsPage customerId={selectedCustomerId} />}
            {activeNav === 'threat-feed' && <ThreatFeedPage />}
            {activeNav === 'data-breaches' && <DataBreachesPage customerId={selectedCustomerId} />}
            {activeNav === '3rd-party' && <ThirdPartiesPage customerId={selectedCustomerId} />}
            {activeNav === 'weekly-digest' && <WeeklyDigestPage />}
            {activeNav === 'ai-assist' && (
              <div className="h-full bg-panel border border-hairline rounded-lg overflow-hidden">
                <AIAssistant selectedCustomerId={selectedCustomerId} role={user?.role} />
              </div>
            )}
            {activeNav === 'technology-inventory' && <TechnologyInventory customerId={selectedCustomerId} />}
            {activeNav === 'customers' && <CustomersPage customerId={selectedCustomerId} role={user?.role} />}
            {activeNav === 'reports' && <ReportsPage />}
            {activeNav === 'settings' && <SettingsPage />}
          </main>
        </div>
      </div>
    </ProtectedRoute>
  );
}

function SecurityPostureDashboard({ customerId }) {
  const [data, setData] = useState(null);
  const [breaches, setBreaches] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedVendor, setSelectedVendor] = useState(null);
  const [selectedBreach, setSelectedBreach] = useState(null);

  useEffect(() => {
    if (!customerId) return;
    async function load() {
      try {
        setLoading(true);
        const [dashData, breachData] = await Promise.all([
          getCustomerDashboard(customerId),
          getDataBreaches(customerId).catch(() => ({ breaches: [] }))
        ]);
        setData(dashData);
        setBreaches(Array.isArray(breachData) ? breachData : (breachData.breaches || []));
        setError(null);
      } catch (err) {
        console.error(err);
        setError('Failed to load dashboard');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [customerId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-pulse text-mist">Loading security posture...</div>
      </div>
    );
  }

  if (error || !data) {
    return <EmptyState message={error || 'No dashboard data available'} />;
  }

  const posture = data.posture || {};
  const alerts = data.alerts || [];
  const vendors = data.vendors || [];
  const exposures = data.exposures || [];
  const incidents = data.incidents || [];
  const relevantBreaches = breaches.filter(b => b.customer_impact === true);

  const criticalAlerts = alerts.filter(a => a.severity === 'CRITICAL');
  const highAlerts = alerts.filter(a => a.severity === 'HIGH');

  return (
    <div className="flex flex-col gap-4 h-full overflow-auto">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-hairline bg-[#0D0F11]">
        <div>
          <h1 className="text-sm font-semibold text-ink uppercase tracking-wider">SECURITY OPERATIONS OVERVIEW</h1>
          <p className="text-[10px] text-mist mt-0.5">Customer: {data.customer?.name || '—'}</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-mist font-mono">
            Last updated: {new Date().toLocaleTimeString()}
          </span>
        </div>
      </div>

      {/* Posture Strip */}
      <div className="flex items-center gap-4 px-4 py-2 bg-void/30 border-b border-hairline">
        <div className="flex items-center gap-2">
          <span className="text-[9px] text-mist uppercase tracking-wider">Overall Posture</span>
          <span className="text-xs font-mono text-ink">{posture.total_vendors || 0} Third Parties</span>
        </div>
        <div className="w-px h-4 bg-hairline" />
        <div className="flex items-center gap-2">
          <span className="text-[9px] text-mist uppercase tracking-wider">Exposures</span>
          <span className="text-xs font-mono text-sev-critical">{posture.total_third_party_exposures || 0}</span>
        </div>
        <div className="w-px h-4 bg-hairline" />
        <div className="flex items-center gap-2">
          <span className="text-[9px] text-mist uppercase tracking-wider">Active Alerts</span>
          <span className="text-xs font-mono text-ember-bright">{posture.open_alerts || 0}</span>
        </div>
        <div className="w-px h-4 bg-hairline" />
        <div className="flex items-center gap-2">
          <span className="text-[9px] text-mist uppercase tracking-wider">Critical</span>
          <span className="text-xs font-mono text-sev-critical">{posture.critical_alerts || 0}</span>
        </div>
        <div className="w-px h-4 bg-hairline" />
        <div className="flex items-center gap-2">
          <span className="text-[9px] text-mist uppercase tracking-wider">Relevant Breaches</span>
          <span className="text-xs font-mono text-ink">{relevantBreaches.length}</span>
        </div>
      </div>

      {/* Main Workspace */}
      <div className="flex-1 overflow-auto p-4 space-y-4">
        {/* Threat Landscape */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <SeverityDistribution items={alerts} />
          <IntelligenceTimeline events={alerts} />
        </div>

        {/* Third-Party Risk Matrix */}
        <RiskMatrix vendors={vendors} onVendorClick={setSelectedVendor} />

        {/* Active Threat Intelligence */}
        <div className="border border-hairline rounded-lg bg-[#0D0F11]">
          <div className="flex items-center justify-between px-4 py-3 border-b border-hairline bg-void/30">
            <h3 className="text-xs font-semibold text-ink uppercase tracking-wider">ACTIVE THREAT INTELLIGENCE</h3>
            <span className="text-[10px] text-mist">{alerts.length} events</span>
          </div>
          <div className="overflow-auto max-h-64">
            <table className="w-full">
              <thead>
                <tr className="border-b border-hairline bg-void/50">
                  <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">SEV</th>
                  <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">TYPE</th>
                  <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">VENDOR</th>
                  <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">TECHNOLOGY</th>
                  <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">TITLE</th>
                  <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">RISK</th>
                  <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">STATUS</th>
                </tr>
              </thead>
              <tbody>
                {alerts.slice(0, 10).map(a => (
                  <tr key={a.id} className="border-b border-hairline/50 last:border-0 hover:bg-void/30 cursor-pointer">
                    <td className="px-3 py-2"><SeverityBadge severity={a.severity} /></td>
                    <td className="px-3 py-2 text-[10px] text-ink uppercase">{a.alert_type?.replace(/_/g, ' ')}</td>
                    <td className="px-3 py-2 text-xs text-ink">{a.vendor || '—'}</td>
                    <td className="px-3 py-2 text-xs text-mist">{a.affected_technology || '—'}</td>
                    <td className="px-3 py-2 text-xs text-ink truncate max-w-xs">{a.title || a.alert_type}</td>
                    <td className="px-3 py-2"><RiskIndicator score={a.risk_score} /></td>
                    <td className="px-3 py-2"><StatusBadge status={a.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {alerts.length === 0 && (
              <div className="p-4 text-center text-xs text-mist">No active threat intelligence</div>
            )}
          </div>
        </div>

        {/* Critical Customer Impact */}
        {(criticalAlerts.length > 0 || relevantBreaches.filter(b => b.severity === 'CRITICAL').length > 0) && (
          <div className="border border-hairline rounded-lg bg-[#0D0F11]">
            <div className="flex items-center justify-between px-4 py-3 border-b border-hairline bg-void/30">
              <h3 className="text-xs font-semibold text-sev-critical uppercase tracking-wider">CRITICAL CUSTOMER IMPACT</h3>
              <span className="text-[10px] text-mist">{criticalAlerts.length + relevantBreaches.filter(b => b.severity === 'CRITICAL').length} items</span>
            </div>
            <div className="space-y-1 p-2">
              {criticalAlerts.slice(0, 5).map(a => (
                <div key={a.id} className="flex items-center gap-3 p-2 bg-void border border-hairline rounded hover:border-sev-critical/50 cursor-pointer">
                  <SeverityBadge severity={a.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-ink truncate">{a.title || a.alert_type}</p>
                    <p className="text-[10px] text-mist">{a.vendor} — {a.affected_technology || 'Unknown'}</p>
                  </div>
                  <RiskIndicator score={a.risk_score} />
                </div>
              ))}
              {relevantBreaches.filter(b => b.severity === 'CRITICAL').slice(0, 3).map(b => (
                <div 
                  key={b.id} 
                  onClick={() => setSelectedBreach(b)}
                  className="flex items-center gap-3 p-2 bg-void border border-hairline rounded hover:border-sev-critical/50 cursor-pointer"
                >
                  <SeverityBadge severity={b.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-ink truncate">BREACH: {b.title}</p>
                    <p className="text-[10px] text-mist">{b.vendor_name} — {b.technology_name || 'Unknown'}</p>
                  </div>
                  <RiskIndicator score={b.risk_score} />
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Data Breach Intelligence */}
        <div className="border border-hairline rounded-lg bg-[#0D0F11]">
          <div className="flex items-center justify-between px-4 py-3 border-b border-hairline bg-void/30">
            <h3 className="text-xs font-semibold text-ink uppercase tracking-wider">DATA BREACH INTELLIGENCE</h3>
            <span className="text-[10px] text-mist">{relevantBreaches.length} relevant breaches</span>
          </div>
          <div className="grid grid-cols-5 gap-2 p-3 border-b border-hairline">
            <div className="text-center">
              <p className="text-lg font-bold text-ink">{relevantBreaches.length}</p>
              <p className="text-[9px] text-mist uppercase">Relevant</p>
            </div>
            <div className="text-center">
              <p className="text-lg font-bold text-sev-critical">{relevantBreaches.filter(b => b.severity === 'CRITICAL').length}</p>
              <p className="text-[9px] text-mist uppercase">Critical</p>
            </div>
            <div className="text-center">
              <p className="text-lg font-bold text-sev-high">{relevantBreaches.filter(b => b.severity === 'HIGH').length}</p>
              <p className="text-[9px] text-mist uppercase">High</p>
            </div>
            <div className="text-center">
              <p className="text-lg font-bold text-ink">{new Set(relevantBreaches.map(b => b.vendor_name)).size}</p>
              <p className="text-[9px] text-mist uppercase">Vendors</p>
            </div>
            <div className="text-center">
              <p className="text-lg font-bold text-ink">{new Set(relevantBreaches.map(b => b.technology_name).filter(Boolean)).size}</p>
              <p className="text-[9px] text-mist uppercase">Technologies</p>
            </div>
          </div>
          <div className="overflow-auto max-h-48">
            <table className="w-full">
              <thead>
                <tr className="border-b border-hairline bg-void/50">
                  <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">SEV</th>
                  <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">BREACH</th>
                  <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">VENDOR</th>
                  <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">TECHNOLOGY</th>
                  <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">IMPACT</th>
                  <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">RISK</th>
                  <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">PUBLISHED</th>
                </tr>
              </thead>
              <tbody>
                {relevantBreaches.slice(0, 8).map(b => (
                  <tr 
                    key={b.id} 
                    onClick={() => setSelectedBreach(b)}
                    className="border-b border-hairline/50 last:border-0 hover:bg-void/30 cursor-pointer"
                  >
                    <td className="px-3 py-2"><SeverityBadge severity={b.severity} /></td>
                    <td className="px-3 py-2 text-xs text-ink truncate max-w-xs">{b.title}</td>
                    <td className="px-3 py-2 text-xs text-mist">{b.vendor_name || '—'}</td>
                    <td className="px-3 py-2 text-xs text-mist">{b.technology_name || '—'}</td>
                    <td className="px-3 py-2">
                      <span className={`text-[10px] font-semibold ${b.customer_impact ? 'text-sev-critical' : 'text-sev-low'}`}>
                        {b.customer_impact ? 'DIRECT' : 'INDIRECT'}
                      </span>
                    </td>
                    <td className="px-3 py-2"><RiskIndicator score={b.risk_score} /></td>
                    <td className="px-3 py-2 text-[10px] text-mist font-mono">
                      {b.published_at ? new Date(b.published_at).toISOString().split('T')[0] : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {relevantBreaches.length === 0 && (
              <div className="p-4 text-center text-xs text-mist">No relevant breaches affecting customer ecosystem</div>
            )}
          </div>
        </div>
      </div>

      {/* Investigation Drawers */}
      {selectedVendor && (
        <VendorInvestigationDrawer vendor={selectedVendor} onClose={() => setSelectedVendor(null)} />
      )}
      {selectedBreach && (
        <BreachInvestigationDrawer breach={selectedBreach} onClose={() => setSelectedBreach(null)} />
      )}
    </div>
  );
}

export default App;