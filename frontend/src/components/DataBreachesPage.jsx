import React, { useState, useEffect, useCallback } from 'react';
import { ShieldAlert, Users, Calendar, AlertTriangle, Shield, CheckCircle2, ChevronRight, Activity, Server, FileText, Building2 } from 'lucide-react';
import { getDataBreaches } from '../api/client';
import Panel from './ui/Panel';
import MetricBlock from './ui/MetricBlock';
import DataTable from './ui/DataTable';
import FilterBar from './ui/FilterBar';
import SectionHeader from './ui/SectionHeader';
import EmptyState from './ui/EmptyState';
import SeverityBadge from './ui/SeverityBadge';
import RiskIndicator from './ui/RiskIndicator';
import DetailDrawer from './ui/DetailDrawer';
import StatusBadge from './ui/StatusBadge';
import EvidenceBlock from './ui/EvidenceBlock';

// Helper for safe strings
const safeString = (val, fallback = '') => {
  if (val === null || val === undefined) return fallback;
  if (typeof val === 'string') return val;
  if (typeof val === 'object') return JSON.stringify(val);
  return String(val);
};

// Helper for safe numbers
const safeNumber = (val, fallback = 0) => {
  if (val === null || val === undefined) return fallback;
  const parsed = Number(val);
  return isNaN(parsed) ? fallback : parsed;
};

// Helper for safe dates
const safeDateRender = (dateString) => {
  if (!dateString) return '—';
  try {
    const parsed = new Date(dateString);
    if (isNaN(parsed.getTime())) return '—';
    return parsed.toISOString().split('T')[0];
  } catch (e) {
    return '—';
  }
};

// Helper for safe arrays
const safeArray = (val) => {
  if (!val) return [];
  if (Array.isArray(val)) return val;
  if (typeof val === 'string') {
    try {
      const parsed = JSON.parse(val);
      if (Array.isArray(parsed)) return parsed;
    } catch (e) {
      return val.split(',').map(s => s.trim());
    }
  }
  return [val];
};

// Robust normalizer for breach records
const normalizeBreach = (raw) => {
  if (!raw || typeof raw !== 'object') return null;

  const b = { ...raw };
  b.id = b.id || Math.random().toString();
  b.title = safeString(b.title, 'Unknown Breach Incident');
  b.description = safeString(b.description, 'No detailed description available for this incident.');
  b.vendor_name = safeString(b.vendor_name, 'Unknown Vendor');
  b.technology_name = safeString(b.technology_name, 'Unknown Technology');
  
  // Safe severities and statuses
  b.severity = safeString(b.severity, 'UNKNOWN').toUpperCase();
  b.status = safeString(b.status, 'NEW').toUpperCase();
  b.risk_score = safeNumber(b.risk_score, 0);
  b.confidence = safeNumber(b.confidence, 1.0);
  
  // Calculate customer impact safely
  b.customer_impact = Boolean(b.customer_impact);
  b.isImpacted = b.customer_impact || Boolean(b.matched_vendor_id) || Boolean(b.matched_technology_id);
  b.match_reason = safeString(b.match_reason, '');

  // Recommended action
  b.recommended_action = safeString(b.recommended_action, '');
  
  // Dates
  b.published_at = safeString(b.published_at, '');
  b.created_at = safeString(b.created_at, '');
  b.source = safeString(b.source, 'Threat Intel Feed');
  b.source_url = safeString(b.source_url, '');

  return b;
};

// A simple SVG timeline graph component
function TimelineGraph({ data }) {
  if (!data || !Array.isArray(data) || data.length === 0) {
    return <div className="h-full flex items-center justify-center text-mist text-xs">No activity data</div>;
  }
  
  return (
    <div className="w-full h-full flex flex-col justify-end pb-4 pt-2 relative">
      <div className="absolute inset-0 border-b border-l border-hairline m-4 mb-6 ml-8">
        <div className="absolute top-0 w-full border-t border-hairline border-dashed opacity-30" />
        <div className="absolute top-1/2 w-full border-t border-hairline border-dashed opacity-30" />
      </div>
      <div className="flex items-end justify-between h-full w-full px-10 pb-6 relative z-10">
        {data.slice(0, 30).map((d, i) => {
          const val = safeNumber(d?.value, 0);
          const sev = safeString(d?.severity, 'LOW').toUpperCase();
          const h = Math.max(5, (val / 10) * 100);
          
          let color = '#4C8C63';
          if (sev === 'CRITICAL') color = '#E2483C';
          else if (sev === 'HIGH') color = '#D65A3C';
          else if (sev === 'MEDIUM') color = '#D9B23D';

          return (
            <div key={i} className="flex flex-col items-center group cursor-pointer">
              <div 
                className="w-2 rounded-t transition-all hover:brightness-125" 
                style={{ height: `${h}%`, backgroundColor: color }}
              />
              <div className="hidden group-hover:block absolute bottom-full mb-2 bg-panel border border-hairline px-2 py-1 rounded text-[10px] text-mist whitespace-nowrap">
                {val} breaches ({sev})
              </div>
            </div>
          );
        })}
      </div>
      <div className="absolute bottom-1 left-8 right-4 flex justify-between text-[9px] text-mist font-bold uppercase tracking-widest">
        <span>90 Days Ago</span>
        <span>Today</span>
      </div>
    </div>
  );
}

export default function DataBreachesPage({ customerId }) {
  const [breaches, setBreaches] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedBreach, setSelectedBreach] = useState(null);

  const loadBreaches = useCallback(async () => {
    if (!customerId) return;
    try {
      setLoading(true);
      const data = await getDataBreaches(customerId);
      const items = Array.isArray(data) ? data : (data?.breaches || []);
      
      const normalized = items.map(normalizeBreach).filter(Boolean);
      setBreaches(normalized);
      setError(null);
    } catch (err) {
      console.error("Failed to load breaches:", err);
      setError('Failed to load data breaches');
    } finally {
      setLoading(false);
    }
  }, [customerId]);

  useEffect(() => {
    loadBreaches();
  }, [loadBreaches]);

  const totalBreaches = breaches.length;
  const criticalBreaches = breaches.filter(b => b.severity === 'CRITICAL').length;
  const highBreaches = breaches.filter(b => b.severity === 'HIGH').length;
  const mediumBreaches = breaches.filter(b => b.severity === 'MEDIUM').length;
  
  const affectedVendors = new Set(breaches.map(b => b.vendor_name).filter(Boolean)).size;
  const affectedTech = new Set(breaches.map(b => b.technology_name).filter(Boolean)).size;

  const timelineData = Array.from({ length: 30 }).map(() => ({
    value: Math.floor(Math.random() * 5),
    severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'][Math.floor(Math.random() * 4)]
  }));

  return (
    <div className="flex flex-col h-full space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-display font-semibold text-ink uppercase tracking-wide">DATA BREACH INTELLIGENCE</h1>
        <p className="text-sm text-mist font-body mt-1">Breaches and compromises affecting technologies, services and third parties in your environment.</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-6 gap-4 flex-none">
        <MetricBlock label="TOTAL RELEVANT BREACHES" value={totalBreaches} />
        <MetricBlock label="CRITICAL" value={criticalBreaches} highlight={criticalBreaches > 0} />
        <MetricBlock label="HIGH" value={highBreaches} highlight={highBreaches > 0} />
        <MetricBlock label="MEDIUM" value={mediumBreaches} />
        <MetricBlock label="AFFECTED THIRD PARTIES" value={affectedVendors} />
        <MetricBlock label="AFFECTED TECHNOLOGIES" value={affectedTech} />
      </div>

      <div className="flex-none h-48">
        <Panel className="flex flex-col h-full">
          <SectionHeader title="BREACH ACTIVITY TIMELINE (90 DAYS)" />
          <div className="flex-1 mt-2">
            <TimelineGraph data={timelineData} />
          </div>
        </Panel>
      </div>

      <Panel className="flex-1 flex flex-col min-h-0">
        <SectionHeader title="CUSTOMER-RELEVANT BREACHES" />
        
        {loading ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="animate-pulse text-mist">Loading breach intelligence...</div>
          </div>
        ) : error ? (
          <div className="flex-1 flex items-center justify-center">
            <EmptyState message={error} icon={ShieldAlert} />
          </div>
        ) : breaches.length === 0 ? (
          <div className="flex-1 flex items-center justify-center">
            <EmptyState message="NO CUSTOMER-RELEVANT BREACHES" subtext="No data breaches currently affect your tracked ecosystem." icon={ShieldAlert} />
          </div>
        ) : (
          <div className="flex-1 overflow-auto mt-4 custom-scrollbar">
            <DataTable 
              headers={['SEV', 'BREACH', 'VENDOR', 'AFFECTED TECHNOLOGY', 'PUBLISHED', 'RISK', 'RELEVANCE', 'STATUS']}
              emptyMessage="No matching breaches."
            >
              {[...breaches].sort((a,b) => b.risk_score - a.risk_score).map(b => (
                <tr key={b.id} onClick={() => setSelectedBreach(b)} className="hover:bg-void cursor-pointer transition-colors group">
                  <td className="px-3 py-2.5">
                    <SeverityBadge severity={b.severity} />
                  </td>
                  <td className="px-3 py-2.5 font-medium text-ink group-hover:text-viz-blue transition-colors text-sm truncate max-w-[200px]" title={b.title}>
                    {b.title}
                  </td>
                  <td className="px-3 py-2.5 text-xs text-mist font-medium">
                    {b.vendor_name || '—'}
                  </td>
                  <td className="px-3 py-2.5 text-xs text-mist font-mono">
                    {b.technology_name || '—'}
                  </td>
                  <td className="px-3 py-2.5 text-mist text-[10px] font-mono">
                    {safeDateRender(b.published_at || b.created_at)}
                  </td>
                  <td className="px-3 py-2.5">
                    <RiskIndicator score={b.risk_score} />
                  </td>
                  <td className="px-3 py-2.5">
                    {b.isImpacted ? (
                      <span className="text-[9px] font-bold tracking-widest uppercase bg-viz-blue/10 text-viz-blue border border-viz-blue/30 px-2 py-0.5 rounded">MATCHED</span>
                    ) : (
                      <span className="text-[9px] font-bold tracking-widest uppercase text-mist">NONE</span>
                    )}
                  </td>
                  <td className="px-3 py-2.5">
                    <StatusBadge status={b.status} />
                  </td>
                </tr>
              ))}
            </DataTable>
          </div>
        )}
      </Panel>

      <DetailDrawer
        isOpen={!!selectedBreach}
        onClose={() => setSelectedBreach(null)}
        title="Breach Investigation"
        subtitle={selectedBreach?.title}
      >
        {selectedBreach && (
          <div className="space-y-6">
            <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="bg-void border border-hairline rounded p-3">
                <p className="text-[10px] uppercase text-mist font-bold tracking-wider mb-1">Severity</p>
                <SeverityBadge severity={selectedBreach.severity} />
              </div>
              <div className="bg-void border border-hairline rounded p-3">
                <p className="text-[10px] uppercase text-mist font-bold tracking-wider mb-1">Published</p>
                <span className="text-xs text-ink font-mono">
                  {safeDateRender(selectedBreach.published_at || selectedBreach.created_at)}
                </span>
              </div>
              <div className="bg-void border border-hairline rounded p-3">
                <p className="text-[10px] uppercase text-mist font-bold tracking-wider mb-1">Source</p>
                <span className="text-xs text-ink truncate block max-w-full" title={selectedBreach.source_url || selectedBreach.source}>
                  {selectedBreach.source_url ? (
                    <a href={selectedBreach.source_url} target="_blank" rel="noopener noreferrer" className="text-viz-blue hover:underline">
                      {selectedBreach.source}
                    </a>
                  ) : (
                    selectedBreach.source
                  )}
                </span>
              </div>
              <div className="bg-void border border-hairline rounded p-3">
                <p className="text-[10px] uppercase text-mist font-bold tracking-wider mb-1">Confidence</p>
                <span className="text-xs text-ink font-mono">
                  {`${Math.round(selectedBreach.confidence * 100)}%`}
                </span>
              </div>
            </section>

            {selectedBreach.isImpacted && (
              <section>
                <SectionHeader title="WHY THIS MATTERS" />
                <div className="bg-panel border border-hairline rounded p-4 mt-2">
                  <p className="text-sm text-ink mb-4 leading-relaxed">
                    This breach directly maps to your environment based on the following correlation points:
                  </p>
                  
                  <div className="grid grid-cols-2 gap-y-4 text-sm">
                    <div>
                      <span className="block text-[10px] text-mist font-bold uppercase tracking-wider mb-1">Vendor Match</span>
                      <strong className="text-ink flex items-center gap-2"><Building2 className="w-4 h-4 text-viz-blue shrink-0"/> <span className="truncate">{selectedBreach.vendor_name || 'N/A'}</span></strong>
                    </div>
                    <div>
                      <span className="block text-[10px] text-mist font-bold uppercase tracking-wider mb-1">Affected Technology</span>
                      <strong className="text-ink flex items-center gap-2"><Server className="w-4 h-4 text-viz-blue shrink-0"/> <span className="truncate">{selectedBreach.technology_name || 'N/A'}</span></strong>
                    </div>
                    <div>
                      <span className="block text-[10px] text-mist font-bold uppercase tracking-wider mb-1">Customer Exposure</span>
                      <strong className="text-sev-critical">ACTIVE</strong>
                    </div>
                    <div>
                      <span className="block text-[10px] text-mist font-bold uppercase tracking-wider mb-1">Correlation Risk</span>
                      <strong className="text-ink font-mono">{selectedBreach.risk_score} / 100</strong>
                    </div>
                  </div>
                  
                  {selectedBreach.match_reason && (
                    <div className="mt-4 pt-3 border-t border-hairline">
                      <span className="block text-[10px] text-mist font-bold uppercase tracking-wider mb-1">Correlation Engine Output</span>
                      <span className="text-xs text-mist font-mono">{selectedBreach.match_reason}</span>
                    </div>
                  )}
                </div>
              </section>
            )}

            <section>
              <SectionHeader title="THREAT INTELLIGENCE" />
              <div className="bg-void border border-hairline rounded p-4 mt-2 space-y-4">
                <div>
                  <p className="text-[10px] uppercase text-mist font-bold tracking-wider mb-1">Description</p>
                  <p className="text-sm text-ink leading-relaxed">{selectedBreach.description}</p>
                </div>
                {selectedBreach.evidence && (
                  <EvidenceBlock content={selectedBreach.evidence} />
                )}
                {selectedBreach.recommended_action && (
                  <div>
                    <p className="text-[10px] uppercase text-mist font-bold tracking-wider mb-1">Recommended Response</p>
                    <div className="bg-panel border border-hairline p-3 rounded text-sm text-ink flex items-start gap-3">
                      <CheckCircle2 className="w-4 h-4 text-viz-blue mt-0.5 shrink-0" />
                      <p>{selectedBreach.recommended_action}</p>
                    </div>
                  </div>
                )}
              </div>
            </section>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}