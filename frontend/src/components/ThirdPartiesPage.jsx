import React, { useState, useEffect, useCallback } from 'react';
import { 
  Building2, ShieldAlert, Shield, Search, Filter, Share2, 
  Database, Server, Globe, FileText, ChevronDown, CheckCircle2,
  XCircle, ArrowUpRight
} from 'lucide-react';
import { getCustomerVendors } from '../api/client'; // or getVendors directly if exposed
import Panel from './ui/Panel';
import MetricBlock from './ui/MetricBlock';
import DataTable from './ui/DataTable';
import SectionHeader from './ui/SectionHeader';
import SeverityBadge from './ui/SeverityBadge';
import RiskIndicator from './ui/RiskIndicator';
import DetailDrawer from './ui/DetailDrawer';
import EmptyState from './ui/EmptyState';
import EcosystemImportModal from './EcosystemImportModal';

// Scatter plot for Vendor Risk Landscape
function VendorLandscape({ data, onSelect }) {
  if (!data || data.length === 0) return <div className="h-full flex items-center justify-center text-mist text-xs">No vendor data</div>;
  
  return (
    <div className="relative w-full h-full bg-void border border-hairline rounded flex">
      <div className="absolute -left-6 top-1/2 -translate-y-1/2 -rotate-90 text-[9px] font-bold text-mist uppercase tracking-widest whitespace-nowrap">
        Business Criticality
      </div>
      <div className="absolute bottom-2 left-1/2 -translate-x-1/2 text-[9px] font-bold text-mist uppercase tracking-widest">
        Security Risk
      </div>

      <div className="flex-1 relative m-8 border-l border-b border-hairline">
        {data.map((v, i) => {
          const x = Math.max(5, Math.min(95, v.risk_score || 0));
          let cVal = 1;
          if (v.criticality === 'CRITICAL') cVal = 4;
          else if (v.criticality === 'HIGH') cVal = 3;
          else if (v.criticality === 'MEDIUM') cVal = 2;
          
          const y = Math.max(5, Math.min(95, ((cVal - 1) / 3 * 100) + (i % 3 - 1) * 2));
          const size = Math.max(12, Math.min(32, 12 + (v.exposures || 0) * 2 + (v.alerts || 0) * 2));
          
          let color = '#4C8C63';
          if (v.risk_score >= 90 || v.criticality === 'CRITICAL') color = '#E2483C';
          else if (v.risk_score >= 70 || v.criticality === 'HIGH') color = '#D65A3C';
          else if (v.risk_score >= 40 || v.criticality === 'MEDIUM') color = '#D9B23D';

          return (
            <div 
              key={v.id}
              onClick={() => onSelect(v)}
              className="absolute rounded-full cursor-pointer transition-all hover:scale-125 hover:z-10 group"
              style={{
                left: `${x}%`,
                bottom: `${y}%`,
                width: size,
                height: size,
                backgroundColor: `${color}80`,
                border: `1px solid ${color}`,
                transform: 'translate(-50%, 50%)'
              }}
            >
              <div className="hidden group-hover:block absolute bottom-full left-1/2 -translate-x-1/2 mb-2 bg-panel border border-hairline px-2 py-1 rounded text-[10px] whitespace-nowrap z-20 shadow-lg">
                <p className="font-bold text-ink">{v.name}</p>
                <p className="text-mist">Risk: {v.risk_score} | Crit: {v.criticality}</p>
                <p className="text-mist mt-1 text-[8px]">{v.exposures} Exposures | {v.alerts} Alerts</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function DonutChart({ data }) {
  const total = data.reduce((acc, curr) => acc + curr.value, 0);
  if (total === 0) return <div className="h-full flex items-center justify-center text-mist text-xs">No data</div>;

  let currentPct = 0;
  const gradientStops = data.map(d => {
    const pct = (d.value / total) * 100;
    const stop = `${d.color} ${currentPct}% ${currentPct + pct}%`;
    currentPct += pct;
    return stop;
  }).join(', ');

  return (
    <div className="flex flex-col items-center justify-center h-full gap-4">
      <div className="relative w-28 h-28 rounded-full flex items-center justify-center"
           style={{ background: `conic-gradient(${gradientStops})` }}>
        <div className="absolute inset-2 bg-panel rounded-full flex flex-col items-center justify-center">
          <span className="text-lg font-bold font-mono text-ink">{total}</span>
        </div>
      </div>
      <div className="flex flex-wrap gap-2 justify-center">
        {data.map(d => (
          <div key={d.label} className="flex items-center gap-1 text-[9px] font-bold text-mist uppercase">
            <div className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: d.color }} />
            {d.label} ({d.value})
          </div>
        ))}
      </div>
    </div>
  );
}

function RiskDriverBar({ label, value, max = 100, color = 'bg-sev-high' }) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100));
  return (
    <div className="flex items-center gap-3 text-[10px] mb-2">
      <div className="w-32 truncate text-mist font-medium uppercase tracking-wider">{label}</div>
      <div className="flex-1 h-1 bg-void rounded-full overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <div className="w-6 text-right font-mono text-ink">{value}</div>
    </div>
  );
}

export default function ThirdPartiesPage({ customerId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showImport, setShowImport] = useState(false);
  const [selectedVendor, setSelectedVendor] = useState(null);
  const [search, setSearch] = useState('');

  const loadData = useCallback(async () => {
    if (!customerId) return;
    try {
      setLoading(true);
      const res = await getCustomerVendors(customerId);
      setData({ vendors: res });
      setError(null);
    } catch (err) {
      console.error(err);
      setError('Failed to load third-party intelligence');
    } finally {
      setLoading(false);
    }
  }, [customerId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  if (loading && !data) {
    return <div className="h-full flex items-center justify-center text-mist animate-pulse">Loading Third-Party Intelligence...</div>;
  }

  if (error) {
    return <div className="h-full flex items-center justify-center"><EmptyState message={error} /></div>;
  }

  if (!data) return null;

  // Use vendor data from API response
  const vendors = data.vendors || [];

  const filteredVendors = vendors.filter(v => (v.vendor || '').toLowerCase().includes(search.toLowerCase()));

  // Derived metrics
  const totalVendors = vendors.length;
  const criticalVendors = vendors.filter(v => v.criticality === 'CRITICAL').length;
  const highRiskVendors = vendors.filter(v => v.risk_score >= 70).length;
  const activeExposures = vendors.reduce((sum, v) => sum + (v.exposures_count || 0), 0);
  const activeAlerts = vendors.reduce((sum, v) => sum + (v.alerts_count || 0), 0);
  const relevantBreaches = vendors.reduce((sum, v) => sum + (v.breaches_count || 0), 0);

  const critDist = [
    { label: 'CRITICAL', value: criticalVendors, color: '#E2483C' },
    { label: 'HIGH', value: vendors.filter(v => v.criticality === 'HIGH').length, color: '#D65A3C' },
    { label: 'MEDIUM', value: vendors.filter(v => v.criticality === 'MEDIUM').length, color: '#D9B23D' },
    { label: 'LOW', value: vendors.filter(v => v.criticality === 'LOW').length, color: '#4C8C63' },
  ];

  return (
    <div className="flex flex-col h-full gap-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between flex-none">
        <div>
          <h1 className="text-2xl font-display font-semibold text-ink tracking-wide">THIRD-PARTY INTELLIGENCE</h1>
          <p className="text-sm text-mist font-body mt-1">Monitor vendor exposure, business criticality, architecture dependencies and threat activity.</p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={() => setShowImport(true)} className="px-4 py-2 bg-viz-blue hover:bg-viz-blue/90 text-white font-semibold rounded text-sm transition-colors flex items-center gap-2">
            <Share2 className="w-4 h-4" />
            IMPORT ECOSYSTEM
          </button>
        </div>
      </div>

      {/* Summary Strip */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4 flex-none">
        <MetricBlock label="TOTAL VENDORS" value={totalVendors} />
        <MetricBlock label="CRITICAL VENDORS" value={criticalVendors} highlight={criticalVendors > 0} />
        <MetricBlock label="HIGH-RISK VENDORS" value={highRiskVendors} highlight={highRiskVendors > 0} />
        <MetricBlock label="ACTIVE EXPOSURES" value={activeExposures} highlight={activeExposures > 0} />
        <MetricBlock label="ACTIVE ALERTS" value={activeAlerts} highlight={activeAlerts > 0} />
        <MetricBlock label="RELEVANT BREACHES" value={relevantBreaches} highlight={relevantBreaches > 0} />
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 flex-none h-72">
        {/* Landscape */}
        <Panel className="xl:col-span-2 flex flex-col">
          <SectionHeader title="VENDOR RISK LANDSCAPE" />
          <div className="flex-1 mt-4">
            <VendorLandscape data={vendors} onSelect={setSelectedVendor} />
          </div>
        </Panel>
        
        {/* Distributions */}
        <Panel className="xl:col-span-1 flex flex-col">
          <SectionHeader title="RISK DISTRIBUTION" />
          <div className="flex-1 grid grid-rows-2 gap-4 mt-2">
            <div className="row-span-1">
              <DonutChart data={critDist} />
            </div>
            <div className="row-span-1 overflow-y-auto custom-scrollbar pt-2 border-t border-hairline">
              <h3 className="text-[9px] font-bold text-mist uppercase tracking-widest mb-2">Top Risk Drivers</h3>
              <RiskDriverBar label="Exposed Technologies" value={activeExposures} max={20} color="bg-sev-critical" />
              <RiskDriverBar label="Active Breaches" value={relevantBreaches} max={10} color="bg-sev-critical" />
            </div>
          </div>
        </Panel>
      </div>

      {/* Table */}
      <Panel className="flex-1 flex flex-col min-h-0">
        <div className="flex items-center justify-between mb-4 flex-none">
          <SectionHeader title="VENDOR INTELLIGENCE" />
          <div className="relative w-64">
            <Search className="w-4 h-4 text-mist absolute left-3 top-1/2 -translate-y-1/2" />
            <input 
              type="text"
              placeholder="Search vendors..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-void border border-hairline rounded pl-9 pr-3 py-1.5 text-sm text-ink focus:outline-none focus:border-viz-blue transition-colors"
            />
          </div>
        </div>
        <div className="flex-1 overflow-auto custom-scrollbar">
          <DataTable 
            headers={['VENDOR', 'CRITICALITY', 'RELEVANCE', 'RISK SCORE', 'TECHNOLOGIES', 'EXPOSURES', 'ALERTS', 'BREACHES', 'LAST INTEL']}
          >
            {filteredVendors.sort((a,b) => b.risk_score - a.risk_score).map(v => (
              <tr key={v.id} onClick={() => setSelectedVendor(v)} className="hover:bg-void cursor-pointer group transition-colors">
                <td className="px-3 py-2.5 font-medium text-ink text-sm group-hover:text-viz-blue">{v.vendor}</td>
                <td className="px-3 py-2.5"><SeverityBadge severity={v.criticality} /></td>
                <td className="px-3 py-2.5 text-[10px] font-bold text-ink bg-void border border-hairline px-2 rounded w-max tracking-wide">
                  {v.criticality === 'CRITICAL' || v.risk_score > 70 ? 'HIGH' : 'MEDIUM'}
                </td>
                <td className="px-3 py-2.5"><RiskIndicator score={v.risk_score} /></td>
                <td className="px-3 py-2.5 text-xs font-mono text-mist">{(v.technologies || []).length}</td>
                <td className="px-3 py-2.5 text-xs font-mono text-mist">{v.exposures_count ?? v.exposures ?? 0}</td>
                <td className="px-3 py-2.5 text-xs font-mono text-mist">{v.alerts_count ?? v.alerts ?? 0}</td>
                <td className="px-3 py-2.5 text-xs font-mono text-mist">{v.breaches_count ?? v.breaches ?? 0}</td>
                <td className="px-3 py-2.5 text-xs text-mist font-mono">{v.last_intelligence_at ? new Date(v.last_intelligence_at).toLocaleDateString() : '—'}</td>
              </tr>
            ))}
          </DataTable>
        </div>
      </Panel>

      {/* Detail Drawer */}
      <DetailDrawer
        isOpen={!!selectedVendor}
        onClose={() => setSelectedVendor(null)}
        title={selectedVendor?.vendor}
        subtitle="Vendor Investigation"
      >
        {selectedVendor && (
          <div className="space-y-6">
            <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="bg-void border border-hairline rounded p-3">
                <p className="text-[10px] uppercase text-mist font-bold tracking-wider mb-1">Risk Score</p>
                <RiskIndicator score={selectedVendor.risk_score} />
              </div>
              <div className="bg-void border border-hairline rounded p-3">
                <p className="text-[10px] uppercase text-mist font-bold tracking-wider mb-1">Criticality</p>
                <SeverityBadge severity={selectedVendor.criticality} />
              </div>
              <div className="bg-void border border-hairline rounded p-3">
                <p className="text-[10px] uppercase text-mist font-bold tracking-wider mb-1">Exposures</p>
                <p className="text-lg font-mono font-bold text-ink">{selectedVendor.exposures_count}</p>
              </div>
              <div className="bg-void border border-hairline rounded p-3">
                <p className="text-[10px] uppercase text-mist font-bold tracking-wider mb-1">Alerts</p>
                <p className="text-lg font-mono font-bold text-ink">{selectedVendor.alerts_count}</p>
              </div>
            </section>

            <section>
              <SectionHeader title="WHY THIS VENDOR MATTERS" />
              <div className="bg-panel border border-hairline rounded p-4 mt-2">
                <p className="text-sm text-ink mb-3 leading-relaxed">
                  <strong className="text-viz-blue">{selectedVendor.vendor}</strong> is classified as a <strong className={selectedVendor.criticality === 'CRITICAL' ? 'text-sev-critical' : 'text-ink'}>{selectedVendor.criticality}</strong> vendor.
                  It has active dependencies on {(selectedVendor.technologies || []).length} technologies in your environment.
                  Currently, there are {selectedVendor.exposures_count} active exposures and {selectedVendor.alerts_count} unresolved alerts.
                </p>
                <div className="grid grid-cols-2 gap-4 border-t border-hairline pt-3 mt-3">
                </div>
              </div>
            </section>

            <section>
              <SectionHeader title="ARCHITECTURE DEPENDENCIES" />
              <div className="mt-2 border border-hairline rounded overflow-hidden">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-void border-b border-hairline">
                      <th className="px-3 py-2 text-[10px] font-bold text-mist uppercase tracking-widest">Technology</th>
                      <th className="px-3 py-2 text-[10px] font-bold text-mist uppercase tracking-widest">Category</th>
                      <th className="px-3 py-2 text-[10px] font-bold text-mist uppercase tracking-widest">Exposure</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(selectedVendor.technologies || []).map((t, i) => (
                      <tr key={i} className="border-b border-hairline last:border-0 bg-panel hover:bg-void transition-colors">
                        <td className="px-3 py-2 text-sm font-medium text-ink flex items-center gap-2"><Server className="w-3.5 h-3.5 text-viz-blue" /> {t.technology}</td>
                        <td className="px-3 py-2 text-xs text-mist uppercase font-mono">{t.category || 'Unknown'}</td>
                        <td className="px-3 py-2 text-xs">
                          {(t.exposures_count || 0) > 0 ? (
                            <span className="text-[9px] font-bold bg-sev-critical/10 text-sev-critical px-2 py-0.5 rounded border border-sev-critical/30">VULNERABLE</span>
                          ) : (
                            <span className="text-[9px] font-bold bg-sev-low/10 text-sev-low px-2 py-0.5 rounded border border-sev-low/30">CLEAN</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </div>
        )}
      </DetailDrawer>

      <EcosystemImportModal 
        isOpen={showImport} 
        onClose={() => setShowImport(false)} 
        customerId={customerId}
        onComplete={() => { setShowImport(false); loadData(); }}
      />
    </div>
  );
}