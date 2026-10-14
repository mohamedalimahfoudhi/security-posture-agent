import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  Shield, AlertTriangle, AlertCircle, TrendingUp, Building2, Globe, Activity,
  RefreshCw, CheckCircle2, ChevronRight, XCircle, Search, Server
} from 'lucide-react';
import { getCustomerDashboard } from '../api/client';
import Panel from './ui/Panel';
import MetricBlock from './ui/MetricBlock';
import DataTable from './ui/DataTable';
import SectionHeader from './ui/SectionHeader';
import SeverityBadge from './ui/SeverityBadge';
import RiskIndicator from './ui/RiskIndicator';
import StatusBadge from './ui/StatusBadge';
import DetailDrawer from './ui/DetailDrawer';
import EmptyState from './ui/EmptyState';

// A simple bubble/scatter chart representation using pure DOM
function ScatterPlot({ data, onSelect }) {
  if (!data || data.length === 0) return <div className="h-full flex items-center justify-center text-mist text-xs">No vendor data available for landscape</div>;
  
  return (
    <div className="relative w-full h-full bg-void border border-hairline rounded flex">
      {/* Y Axis Label */}
      <div className="absolute -left-6 top-1/2 -translate-y-1/2 -rotate-90 text-[9px] font-bold text-mist uppercase tracking-widest whitespace-nowrap">
        Business Criticality
      </div>
      
      {/* X Axis Label */}
      <div className="absolute bottom-2 left-1/2 -translate-x-1/2 text-[9px] font-bold text-mist uppercase tracking-widest">
        Security Risk
      </div>

      <div className="flex-1 relative m-8 border-l border-b border-hairline">
        {data.map((v, i) => {
          // Normalize risk (0-100) and criticality (LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4)
          const x = Math.max(5, Math.min(95, v.risk_score || 0));
          
          let cVal = 1;
          if (v.criticality === 'CRITICAL') cVal = 4;
          else if (v.criticality === 'HIGH') cVal = 3;
          else if (v.criticality === 'MEDIUM') cVal = 2;
          
          // Add slight jitter to y to avoid perfect overlaps
          const y = Math.max(5, Math.min(95, ((cVal - 1) / 3 * 100) + (i % 3 - 1) * 2));
          
          const size = Math.max(12, Math.min(32, 12 + (v.exposures || 0) * 2 + (v.alerts || 0) * 2));
          
          let color = '#4C8C63'; // LOW
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
                <p className="font-bold text-ink">{v.vendor || v.name}</p>
                <p className="text-mist">Risk: {v.risk_score} | Crit: {v.criticality}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function RiskBar({ label, value, max = 100 }) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100));
  let color = 'bg-sev-low';
  if (value >= 90) color = 'bg-sev-critical';
  else if (value >= 70) color = 'bg-sev-high';
  else if (value >= 40) color = 'bg-sev-medium';

  return (
    <div className="flex items-center gap-3 text-xs mb-2">
      <div className="w-24 truncate text-mist font-medium">{label}</div>
      <div className="flex-1 h-1.5 bg-void rounded-full overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <div className="w-6 text-right font-mono text-ink">{value}</div>
    </div>
  );
}

function DonutChart({ data }) {
  // Simple CSS conic-gradient donut
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
      <div className="relative w-32 h-32 rounded-full flex items-center justify-center"
           style={{ background: `conic-gradient(${gradientStops})` }}>
        <div className="absolute inset-2 bg-panel rounded-full flex flex-col items-center justify-center">
          <span className="text-2xl font-bold font-mono text-ink">{total}</span>
          <span className="text-[9px] uppercase tracking-wider text-mist font-bold">Total</span>
        </div>
      </div>
      <div className="flex flex-wrap gap-3 justify-center">
        {data.map(d => (
          <div key={d.label} className="flex items-center gap-1.5 text-[10px] font-bold text-mist uppercase">
            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} />
            {d.label} ({d.value})
          </div>
        ))}
      </div>
    </div>
  );
}

function TimeSeriesChart({ alerts }) {
  const buckets = useMemo(() => {
    if (!alerts || alerts.length === 0) return [];
    const byDay = {};
    alerts.forEach(a => {
      if (!a.created_at) return;
      const day = a.created_at.slice(0, 10); // YYYY-MM-DD
      if (!byDay[day]) byDay[day] = { date: day, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
      const sev = a.severity || 'LOW';
      byDay[day][sev] = (byDay[day][sev] || 0) + 1;
    });
    return Object.values(byDay).sort((a, b) => a.date.localeCompare(b.date)).slice(-14);
  }, [alerts]);

  if (buckets.length === 0) return <div className="h-full flex items-center justify-center text-mist text-xs">No threat activity data</div>;

  const maxVal = Math.max(1, ...buckets.map(b => b.CRITICAL + b.HIGH + b.MEDIUM + b.LOW));
  const sevColors = { CRITICAL: '#F87171', HIGH: '#FB923C', MEDIUM: '#FBBF24', LOW: '#60A5FA' };

  return (
    <div className="w-full h-full bg-void border border-hairline rounded relative overflow-hidden flex flex-col">
      {/* Grid background */}
      <div className="absolute inset-0 opacity-10" style={{
        backgroundImage: 'linear-gradient(#2d333b 1px, transparent 1px), linear-gradient(90deg, #2d333b 1px, transparent 1px)',
        backgroundSize: '20px 20px'
      }} />
      {/* Chart area */}
      <div className="flex-1 flex items-end gap-1 px-3 pt-6 pb-1 relative z-10">
        {buckets.map((b, i) => {
          const total = b.CRITICAL + b.HIGH + b.MEDIUM + b.LOW;
          const pct = (total / maxVal) * 100;
          // Stacked segments
          const segments = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            .filter(s => b[s] > 0)
            .map(s => ({ sev: s, count: b[s], pctOfBar: (b[s] / total) * 100 }));
          return (
            <div key={b.date} className="flex-1 flex flex-col items-center group" style={{ minWidth: 0 }}>
              {/* Tooltip */}
              <div className="hidden group-hover:block absolute bottom-full mb-1 bg-panel border border-hairline px-2 py-1 rounded text-[9px] whitespace-nowrap z-20 shadow-lg">
                <p className="font-bold text-ink">{b.date}</p>
                {segments.map(s => <p key={s.sev} style={{ color: sevColors[s.sev] }}>{s.sev}: {s.count}</p>)}
              </div>
              {/* Bar */}
              <div className="w-full rounded-t overflow-hidden transition-all" style={{ height: `${Math.max(4, pct)}%` }}>
                {segments.map(s => (
                  <div key={s.sev} style={{ height: `${s.pctOfBar}%`, backgroundColor: sevColors[s.sev], opacity: 0.85 }} />
                ))}
              </div>
            </div>
          );
        })}
      </div>
      {/* X-axis labels */}
      <div className="flex gap-1 px-3 pb-1.5 relative z-10">
        {buckets.map((b, i) => (
          <div key={b.date} className="flex-1 text-center text-[8px] font-mono text-mist truncate" style={{ minWidth: 0 }}>
            {i === 0 || i === buckets.length - 1 || buckets.length <= 7 ? b.date.slice(5) : ''}
          </div>
        ))}
      </div>
      {/* Legend */}
      <div className="flex gap-3 justify-center px-3 pb-2 relative z-10">
        {Object.entries(sevColors).map(([s, c]) => (
          <div key={s} className="flex items-center gap-1 text-[9px] font-bold text-mist uppercase">
            <div className="w-2 h-2 rounded-sm" style={{ backgroundColor: c }} />{s}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function CustomerDashboardPage({ customerId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(new Date());

  const loadData = useCallback(async () => {
    if (!customerId) return;
    try {
      setLoading(true);
      const res = await getCustomerDashboard(customerId);
      setData(res);
      setError(null);
      setLastUpdated(new Date());
    } catch (err) {
      console.error(err);
      setError('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  }, [customerId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  if (loading && !data) {
    return <div className="h-full flex items-center justify-center text-mist animate-pulse">Loading Intelligence Workspace...</div>;
  }

  if (error) {
    return <div className="h-full flex items-center justify-center"><EmptyState message={error} /></div>;
  }

  if (!data) return null;

  const { posture, alerts = [] } = data;
  
  // Transform backend vendor data for charts
  const vendors = data.vendors || []; 
  const displayVendors = vendors;

  // Severity Distribution for donut
  const sevDist = [
    { label: 'CRITICAL', value: posture.critical_alerts || 0, color: '#E2483C' },
    { label: 'HIGH', value: Math.floor((posture.open_alerts - posture.critical_alerts) * 0.5) || 0, color: '#D65A3C' },
    { label: 'MEDIUM', value: Math.floor((posture.open_alerts - posture.critical_alerts) * 0.3) || 0, color: '#D9B23D' },
    { label: 'LOW', value: Math.floor((posture.open_alerts - posture.critical_alerts) * 0.2) || 0, color: '#4C8C63' },
  ];

  return (
    <div className="flex flex-col h-full gap-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between flex-none">
        <div>
          <h1 className="text-2xl font-display font-semibold text-ink tracking-wide">SECURITY OPERATIONS OVERVIEW</h1>
          <p className="text-sm text-mist font-body mt-1">Real-time intelligence summary and security posture for your organization.</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs font-mono text-mist">Last updated: {lastUpdated.toLocaleTimeString()}</span>
          <button onClick={loadData} className="p-2 bg-void border border-hairline rounded hover:bg-surface text-mist hover:text-ink transition-colors">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* KPI Strip */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 flex-none">
        <MetricBlock label="OVERALL POSTURE" value={posture.overall_risk} subtext="Risk Score" highlight={posture.overall_risk >= 70} />
        <MetricBlock label="THIRD PARTIES" value={posture.total_vendors} subtext={`${posture.critical_vendors} Critical`} />
        <MetricBlock label="ACTIVE EXPOSURES" value={posture.total_third_party_exposures} subtext="Exposed Assets" highlight={posture.total_third_party_exposures > 0} />
        <MetricBlock label="ACTIVE ALERTS" value={posture.open_alerts} subtext={`${posture.critical_alerts} Critical`} highlight={posture.critical_alerts > 0} />
        <MetricBlock label="RELEVANT BREACHES" value={data.new_breaches?.length || 0} subtext="Customer Impacted" highlight={(data.new_breaches?.length || 0) > 0} />
      </div>

      {/* Main Grid */}
      <div className="flex-1 grid grid-cols-1 xl:grid-cols-4 gap-6 min-h-0">
        
        {/* Left/Center Column - Charts & Table */}
        <div className="xl:col-span-3 flex flex-col gap-6 min-h-0 overflow-y-auto pr-2 custom-scrollbar">
          
          {/* Charts Row 1 */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 h-64 flex-none">
            <Panel className="flex flex-col">
              <SectionHeader title="THREAT ACTIVITY" />
              <div className="flex-1 mt-2">
                <TimeSeriesChart alerts={alerts} />
              </div>
            </Panel>
            
            <Panel className="flex flex-col">
              <SectionHeader title="THREAT SEVERITY DISTRIBUTION" />
              <div className="flex-1 mt-2">
                <DonutChart data={sevDist} />
              </div>
            </Panel>
          </div>

          {/* Charts Row 2 */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 h-72 flex-none">
            <Panel className="flex flex-col">
              <SectionHeader title="THIRD-PARTY RISK LANDSCAPE" />
              <div className="flex-1 mt-2 py-4">
                <ScatterPlot data={displayVendors} onSelect={() => {}} />
              </div>
            </Panel>

            <Panel className="flex flex-col overflow-hidden">
              <SectionHeader title="RISK BY VENDOR" />
              <div className="flex-1 mt-4 overflow-y-auto custom-scrollbar">
                {displayVendors.sort((a,b) => b.risk_score - a.risk_score).map(v => (
                  <RiskBar key={v.id} label={v.vendor || v.name} value={v.risk_score} />
                ))}
              </div>
            </Panel>
          </div>

          {/* Vendors Table */}
          <Panel className="flex-none">
            <SectionHeader title="TOP THIRD-PARTY VENDORS" />
            <div className="mt-4">
              <DataTable 
                headers={['VENDOR', 'CRITICALITY', 'RELEVANCE', 'RISK SCORE']}
              >
                {displayVendors.slice(0, 5).map(v => (
                  <tr key={v.id} className="hover:bg-void cursor-pointer group transition-colors">
                    <td className="px-3 py-2 font-medium text-ink text-sm group-hover:text-viz-blue">{v.vendor}</td>
                    <td className="px-3 py-2"><SeverityBadge severity={v.criticality} /></td>
                    <td className="px-3 py-2 text-xs font-bold text-mist uppercase">{v.criticality === 'CRITICAL' ? 'HIGH' : 'MEDIUM'}</td>
                    <td className="px-3 py-2"><RiskIndicator score={v.risk_score} /></td>
                  </tr>
                ))}
              </DataTable>
            </div>
          </Panel>
        </div>

        {/* Right Sidebar - Intelligence Column */}
        <div className="xl:col-span-1 flex flex-col gap-4 overflow-y-auto custom-scrollbar">
          <h2 className="text-xs font-display font-bold text-ink uppercase tracking-widest border-b border-hairline pb-2 mb-2">CRITICAL INTELLIGENCE</h2>
          
          <div className="space-y-4">
            <h3 className="text-[10px] text-mist font-bold uppercase tracking-wider">Recent Alerts</h3>
            {alerts.slice(0, 5).map(a => (
              <div key={a.id} className="bg-panel border border-hairline rounded p-3 hover:border-mist/30 transition-colors cursor-pointer group">
                <div className="flex items-center gap-2 mb-1.5">
                  <div className={`w-2 h-2 rounded-full ${a.severity === 'CRITICAL' ? 'bg-sev-critical' : a.severity === 'HIGH' ? 'bg-sev-high' : 'bg-sev-medium'}`} />
                  <span className="text-[10px] font-mono text-mist uppercase truncate">{a.vendor || 'Unknown Vendor'}</span>
                </div>
                <p className="text-sm font-medium text-ink leading-tight group-hover:text-viz-blue">{a.title || a.alert_type.replace(/_/g, ' ')}</p>
                <div className="flex justify-between items-center mt-2 pt-2 border-t border-hairline">
                  <span className="text-[9px] text-mist font-mono">{a.affected_technology || '—'}</span>
                  <span className="text-[9px] text-mist font-mono">{a.created_at ? new Date(a.created_at).toLocaleDateString() : '—'}</span>
                </div>
              </div>
            ))}

            {alerts.length === 0 && (
              <div className="p-4 bg-void border border-hairline rounded text-center">
                <p className="text-xs text-mist">No recent alerts</p>
              </div>
            )}
          </div>
          
          <div className="space-y-4 mt-4 pt-4 border-t border-hairline">
            <h3 className="text-[10px] text-mist font-bold uppercase tracking-wider">Relevant Breaches</h3>
            {(data.new_breaches || []).slice(0, 3).map(b => (
              <div key={b.id} className="bg-panel border border-hairline rounded p-3 hover:border-mist/30 transition-colors cursor-pointer group">
                <div className="flex items-center gap-2 mb-1.5">
                  <Shield className="w-3 h-3 text-sev-high" />
                  <span className="text-[10px] font-mono text-mist uppercase truncate">{b.vendor || 'Unknown Vendor'}</span>
                </div>
                <p className="text-sm font-medium text-ink leading-tight group-hover:text-viz-blue">{b.title || 'Data Breach Recorded'}</p>
              </div>
            ))}
            
            {!(data.new_breaches?.length) && (
              <div className="p-4 bg-void border border-hairline rounded text-center">
                <p className="text-xs text-mist">No recent breaches</p>
              </div>
            )}
          </div>

        </div>

      </div>
    </div>
  );
}
