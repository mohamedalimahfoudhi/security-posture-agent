import React, { useState, useEffect, useCallback } from 'react';
import { AlertTriangle, Clock, Activity, Target, Building2, Database, ShieldAlert, ExternalLink } from 'lucide-react';
import { apiFetch, getCustomerAlerts, getAlertDetail, updateAlertStatus } from '../api/client';
import Panel from './ui/Panel';
import MetricBlock from './ui/MetricBlock';
import DataTable from './ui/DataTable';
import FilterBar from './ui/FilterBar';
import SectionHeader from './ui/SectionHeader';
import EmptyState from './ui/EmptyState';
import SeverityBadge from './ui/SeverityBadge';
import RiskIndicator from './ui/RiskIndicator';
import StatusBadge from './ui/StatusBadge';
import DetailDrawer from './ui/DetailDrawer';
import EvidenceBlock from './ui/EvidenceBlock';

export default function AlertsPage({ customerId }) {
  const safeDateRender = (dateString) => {
    if (!dateString) return '—';
    try {
      const d = new Date(dateString);
      if (isNaN(d.getTime())) return '—';
      return d.toISOString().split('T')[0];
    } catch (e) {
      return '—';
    }
  };

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  const [search, setSearch] = useState('');
  const [filters, setFilters] = useState({
    severity: { value: 'ALL', options: [
      { value: 'ALL', label: 'All Severities' },
      { value: 'CRITICAL', label: 'Critical' },
      { value: 'HIGH', label: 'High' },
      { value: 'MEDIUM', label: 'Medium' },
      { value: 'LOW', label: 'Low' }
    ]},
    status: { value: 'ALL', options: [
      { value: 'ALL', label: 'All Statuses' },
      { value: 'NEW', label: 'New' },
      { value: 'ACKNOWLEDGED', label: 'Acknowledged' },
      { value: 'IN_PROGRESS', label: 'In Progress' },
      { value: 'MITIGATED', label: 'Mitigated' },
      { value: 'RESOLVED', label: 'Resolved' },
      { value: 'DISMISSED', label: 'Dismissed' }
    ]},
    type: { value: 'ALL', options: [
      { value: 'ALL', label: 'All Types' },
      { value: 'VULNERABILITY', label: 'Vulnerability' },
      { value: 'BREACH', label: 'Data Breach' },
      { value: 'RANSOMWARE', label: 'Ransomware' },
      { value: 'SECURITY_INCIDENT', label: 'Security Incident' },
      { value: 'ATTACK_TECHNIQUE', label: 'Attack Technique' },
      { value: 'ARCHITECTURE_CHANGE', label: 'Architecture Change' },
      { value: 'EXTERNAL_EXPOSURE', label: 'External Exposure' },
      { value: 'OTHER', label: 'Other' }
    ]}
  });

  const [selectedAlert, setSelectedAlert] = useState(null);
  const [alertDetail, setAlertDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const loadAlerts = useCallback(async () => {
    if (!customerId) return;
    try {
      setLoading(true);
      const data = await getCustomerAlerts(customerId);
      setAlerts(Array.isArray(data) ? data : []);
      setError(null);
    } catch (err) {
      console.error(err);
      setError('Failed to load alerts');
    } finally {
      setLoading(false);
    }
  }, [customerId]);

  useEffect(() => {
    loadAlerts();
  }, [loadAlerts]);

  // Derived metrics
  const totalAlerts = alerts.length;
  const criticalAlerts = alerts.filter(a => a.severity === 'CRITICAL').length;
  const highAlerts = alerts.filter(a => a.severity === 'HIGH').length;
  const mediumAlerts = alerts.filter(a => a.severity === 'MEDIUM').length;
  const lowAlerts = alerts.filter(a => a.severity === 'LOW').length;
  const newAlerts = alerts.filter(a => a.status === 'NEW').length;
  const inProgress = alerts.filter(a => a.status === 'IN_PROGRESS').length;
  const mitigated = alerts.filter(a => a.status === 'MITIGATED').length;
  const resolved = alerts.filter(a => a.status === 'RESOLVED').length;
  const dismissed = alerts.filter(a => a.status === 'DISMISSED').length;

  // Filtering
  const filteredAlerts = alerts.filter(a => {
    const term = search.toLowerCase();
    const matchesSearch = 
      (a.vendor || '').toLowerCase().includes(term) || 
      (a.affected_technology || '').toLowerCase().includes(term) ||
      (a.title || a.alert_type || '').toLowerCase().includes(term);
      
    const matchesSev = filters.severity.value === 'ALL' || a.severity === filters.severity.value;
    const matchesStatus = filters.status.value === 'ALL' || a.status === filters.status.value;
    const matchesType = filters.type.value === 'ALL' || a.alert_type === filters.type.value;
    
    return matchesSearch && matchesSev && matchesStatus && matchesType;
  });

  const handleFilterChange = (key, val) => {
    setFilters(prev => ({ ...prev, [key]: { ...prev[key], value: val } }));
  };

  const handleAlertClick = async (alert) => {
    setSelectedAlert(alert);
    setDetailLoading(true);
    setAlertDetail(null);
    try {
      const detail = await getAlertDetail(alert.id);
      setAlertDetail(detail);
    } catch (err) {
      console.error('Failed to load alert detail', err);
      setAlertDetail(alert);
    } finally {
      setDetailLoading(false);
    }
  };

  const updateStatus = async (status) => {
    if (!selectedAlert) return;
    try {
      await updateAlertStatus(selectedAlert.id, status);
      loadAlerts();
      setSelectedAlert({ ...selectedAlert, status });
      if (alertDetail) setAlertDetail({ ...alertDetail, status });
    } catch (err) {
      console.error('Failed to update status', err);
    }
  };

  return (
    <div className="flex flex-col h-full space-y-6">
      <div>
        <h1 className="text-2xl font-display font-semibold text-ink uppercase tracking-wide">SECURITY ALERTS</h1>
        <p className="text-sm text-mist font-body mt-1">SOC investigation workspace for ecosystem threats</p>
      </div>

      {/* Summary Metrics */}
      <Panel className="flex-none">
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
          <MetricBlock label="Total" value={totalAlerts} highlight />
          <MetricBlock label="Critical" value={criticalAlerts} highlight={criticalAlerts > 0} />
          <MetricBlock label="High" value={highAlerts} highlight={highAlerts > 0} />
          <MetricBlock label="Medium" value={mediumAlerts} highlight={mediumAlerts > 0} />
          <MetricBlock label="Low" value={lowAlerts} highlight={lowAlerts > 0} />
          <MetricBlock label="New" value={newAlerts} highlight={newAlerts > 0} />
          <MetricBlock label="In Progress" value={inProgress} highlight={inProgress > 0} />
          <MetricBlock label="Resolved" value={resolved} highlight={resolved > 0} />
        </div>
      </Panel>

      {/* Status Breakdown */}
      <Panel className="flex-none">
        <div className="flex flex-wrap gap-2">
          {[
            { label: 'NEW', count: newAlerts, color: 'text-viz-blue' },
            { label: 'ACKNOWLEDGED', count: alerts.filter(a => a.status === 'ACKNOWLEDGED').length, color: 'text-mist' },
            { label: 'IN PROGRESS', count: inProgress, color: 'text-ember-bright' },
            { label: 'MITIGATED', count: mitigated, color: 'text-viz-teal' },
            { label: 'RESOLVED', count: resolved, color: 'text-sev-low' },
            { label: 'DISMISSED', count: dismissed, color: 'text-mist' }
          ].map(s => (
            <div key={s.label} className="flex items-center gap-2 px-3 py-1.5 bg-[#1A1E20] border border-hairline rounded">
              <span className={`text-xs font-bold ${s.color}`}>{s.count}</span>
              <span className="text-[10px] text-mist font-bold tracking-wider">{s.label}</span>
            </div>
          ))}
        </div>
      </Panel>

      {/* Main Content */}
      <Panel className="flex-1 flex flex-col">
        <FilterBar 
          search={search} 
          onSearchChange={setSearch} 
          filters={filters} 
          onFilterChange={handleFilterChange} 
          placeholder="Search alerts, vendors, technologies..."
        />
        
        {loading ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="animate-pulse text-mist">Loading alerts...</div>
          </div>
        ) : error ? (
          <div className="flex-1 flex items-center justify-center">
            <EmptyState message={error} />
          </div>
        ) : (
          <div className="flex-1 overflow-hidden flex flex-col">
            <DataTable 
              headers={['SEV', 'TYPE', 'ALERT', 'VENDOR', 'TECHNOLOGY', 'RISK', 'STATUS', 'UPDATED']}
              emptyMessage="No active alerts."
            >
              {filteredAlerts.map(a => (
                <tr key={a.id} onClick={() => handleAlertClick(a)} className="hover:bg-void cursor-pointer transition-colors group">
                  <td className="px-4 py-3">
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td className="px-4 py-3 text-[10px] text-mist font-bold uppercase tracking-wider">
                    {a.alert_type?.replace(/_/g, ' ')}
                  </td>
                  <td className="px-4 py-3 font-medium text-ink group-hover:text-viz-blue transition-colors truncate max-w-xs">
                    {a.title || a.alert_type}
                  </td>
                  <td className="px-4 py-3 text-sm text-mist">
                    {a.vendor || 'Unknown'}
                  </td>
                  <td className="px-4 py-3 text-sm text-mist">
                    {a.affected_technology || 'Unknown'}
                  </td>
                  <td className="px-4 py-3">
                    <RiskIndicator score={a.risk_score} />
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={a.status} />
                  </td>
                  <td className="px-4 py-3 text-mist text-xs font-mono">
                    {safeDateRender(a.updated_at || a.created_at)}
                  </td>
                </tr>
              ))}
            </DataTable>
          </div>
        )}
      </Panel>

      {/* Alert Detail Drawer */}
      <DetailDrawer
        isOpen={!!selectedAlert}
        onClose={() => { setSelectedAlert(null); setAlertDetail(null); }}
        title="Alert Investigation"
        subtitle={selectedAlert?.title || selectedAlert?.alert_type}
      >
        {detailLoading ? (
          <div className="flex justify-center py-12">
            <div className="animate-pulse text-mist text-sm font-medium tracking-widest uppercase">Loading...</div>
          </div>
        ) : alertDetail ? (
          <div className="space-y-8">
            {/* Alert Overview */}
            <section>
              <SectionHeader title="ALERT OVERVIEW" />
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Panel className="bg-[#1A1E20]">
                  <p className="text-[10px] uppercase text-mist font-bold mb-1">SEVERITY</p>
                  <SeverityBadge severity={alertDetail.severity} />
                </Panel>
                <Panel className="bg-[#1A1E20]">
                  <p className="text-[10px] uppercase text-mist font-bold mb-1">TYPE</p>
                  <span className="text-[10px] text-ink font-mono bg-void px-2 py-0.5 rounded border border-hairline uppercase">
                    {alertDetail.alert_type}
                  </span>
                </Panel>
                <Panel className="bg-[#1A1E20]">
                  <p className="text-[10px] uppercase text-mist font-bold mb-1">RISK</p>
                  <RiskIndicator score={alertDetail.risk_score} showLabel />
                </Panel>
                <Panel className="bg-[#1A1E20]">
                  <p className="text-[10px] uppercase text-mist font-bold mb-1">STATUS</p>
                  <StatusBadge status={alertDetail.status} />
                </Panel>
              </div>
              <div className="grid grid-cols-2 gap-4 mt-4">
                  <div className="flex justify-between items-center bg-[#1A1E20] px-3 py-2 rounded text-xs border border-hairline">
                    <span className="text-mist uppercase font-bold tracking-wider">Detected</span>
                    <span className="text-ink font-mono font-medium">
                      {safeDateRender(alertDetail.created_at)}
                    </span>
                  </div>
                  <div className="flex justify-between items-center bg-[#1A1E20] px-3 py-2 rounded text-xs border border-hairline">
                    <span className="text-mist uppercase font-bold tracking-wider">Updated</span>
                    <span className="text-ink font-mono font-medium">
                      {safeDateRender(alertDetail.updated_at)}
                    </span>
                  </div>
              </div>
            </section>

            {/* Customer */}
            <section>
              <SectionHeader title="CUSTOMER" />
              <div className="bg-[#1A1E20] border border-hairline rounded p-4">
                <p className="text-sm font-medium text-ink">Customer #{alertDetail.customer_id || '—'}</p>
              </div>
            </section>

            {/* Vendor */}
            <section>
              <SectionHeader title="VENDOR" />
              <div className="bg-[#1A1E20] border border-hairline rounded p-4">
                <div className="flex items-center gap-3">
                  <Building2 className="w-5 h-5 text-viz-blue" />
                  <div>
                    <p className="font-semibold text-ink text-sm">{alertDetail.vendor || 'Unknown Vendor'}</p>
                    <p className="text-xs text-mist mt-0.5">Criticality: {alertDetail.vendor_criticality || 'UNKNOWN'}</p>
                  </div>
                </div>
              </div>
            </section>

            {/* Affected Technology */}
            {alertDetail.affected_technology && (
              <section>
                <SectionHeader title="AFFECTED TECHNOLOGY" />
                <div className="bg-[#1A1E20] border border-hairline rounded p-4">
                  <div className="flex items-center gap-3">
                    <Database className="w-5 h-5 text-viz-teal" />
                    <div>
                      <p className="font-semibold text-ink text-sm">{alertDetail.affected_technology}</p>
                      <p className="text-xs text-mist mt-0.5">Technology in customer ecosystem</p>
                    </div>
                  </div>
                </div>
              </section>
            )}

            {/* Customer Impact */}
            <section>
              <SectionHeader title="CUSTOMER IMPACT" />
              <div className="bg-[#1A1E20] border border-hairline rounded p-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-[10px] uppercase text-mist font-bold mb-1">EXPOSURE</p>
                    <span className="text-xs font-semibold text-sev-critical">
                      {alertDetail.exposure_count > 0 ? 'EXPOSED' : 'NO DIRECT EXPOSURE'}
                    </span>
                  </div>
                  <div>
                    <p className="text-[10px] uppercase text-mist font-bold mb-1">RISK SCORE</p>
                    <RiskIndicator score={alertDetail.risk_score} showLabel />
                  </div>
                </div>
                {alertDetail.business_relevance && (
                  <div className="mt-3 pt-3 border-t border-hairline">
                    <p className="text-[10px] uppercase text-mist font-bold mb-1">BUSINESS RELEVANCE</p>
                    <p className="text-sm text-ink">{alertDetail.business_relevance}</p>
                  </div>
                )}
              </div>
            </section>

            {/* Threat Intelligence */}
            <section>
              <SectionHeader title="THREAT INTELLIGENCE" />
              <div className="bg-[#1A1E20] border border-hairline rounded p-4">
                {alertDetail.description && (
                  <div className="mb-3">
                    <p className="text-[10px] uppercase text-mist font-bold mb-1">DESCRIPTION</p>
                    <p className="text-sm text-ink">{alertDetail.description}</p>
                  </div>
                )}
                {alertDetail.cve_id && (
                  <div className="mb-3">
                    <p className="text-[10px] uppercase text-mist font-bold mb-1">CVE ID</p>
                    <span className="text-sm font-mono text-ink bg-void px-2 py-1 rounded border border-hairline">
                      {alertDetail.cve_id}
                    </span>
                  </div>
                )}
                {alertDetail.evidence && <EvidenceBlock content={alertDetail.evidence} />}
                {alertDetail.source_url && (
                  <div className="mt-3">
                    <a href={alertDetail.source_url} target="_blank" rel="noreferrer" className="text-xs text-viz-blue inline-flex items-center gap-1">
                      <ExternalLink className="w-3 h-3" /> View Source
                    </a>
                  </div>
                )}
              </div>
            </section>

            {/* Recommended Response */}
            {alertDetail.recommended_action && (
              <section>
                <SectionHeader title="RECOMMENDED RESPONSE" />
                <div className="bg-[#1A1E20] border border-hairline rounded p-4">
                  <p className="text-sm text-ink">{alertDetail.recommended_action}</p>
                </div>
              </section>
            )}

            {/* Investigation Actions */}
            <section>
              <SectionHeader title="INVESTIGATION ACTIONS" />
              <div className="bg-[#1A1E20] border border-hairline rounded p-4">
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => updateStatus('ACKNOWLEDGED')}
                    className="px-3 py-1.5 text-xs font-bold text-ink bg-void border border-hairline rounded hover:bg-void/80 transition-colors"
                  >
                    ACKNOWLEDGE
                  </button>
                  <button
                    onClick={() => updateStatus('IN_PROGRESS')}
                    className="px-3 py-1.5 text-xs font-bold text-ink bg-void border border-hairline rounded hover:bg-void/80 transition-colors"
                  >
                    IN PROGRESS
                  </button>
                  <button
                    onClick={() => updateStatus('MITIGATED')}
                    className="px-3 py-1.5 text-xs font-bold text-ink bg-void border border-hairline rounded hover:bg-void/80 transition-colors"
                  >
                    MITIGATE
                  </button>
                  <button
                    onClick={() => updateStatus('RESOLVED')}
                    className="px-3 py-1.5 text-xs font-bold text-sev-low bg-sev-low/20 border border-sev-low/30 rounded hover:bg-sev-low/30 transition-colors"
                  >
                    RESOLVE
                  </button>
                  <button
                    onClick={() => updateStatus('DISMISSED')}
                    className="px-3 py-1.5 text-xs font-bold text-mist bg-void border border-hairline rounded hover:bg-void/80 transition-colors"
                  >
                    DISMISS
                  </button>
                </div>
              </div>
            </section>

            {/* Email Notifications */}
            {alertDetail.email_notifications && alertDetail.email_notifications.length > 0 && (
              <section>
                <SectionHeader title="EMAIL NOTIFICATIONS" />
                <div className="bg-[#1A1E20] border border-hairline rounded p-4">
                  <div className="space-y-2">
                    {alertDetail.email_notifications.map((notif, idx) => (
                      <div key={idx} className="flex items-center justify-between text-xs">
                        <span className="text-ink">{notif.recipient}</span>
                        <span className="text-mist font-mono">{notif.sent_at ? safeDateRender(notif.sent_at) : 'Pending'}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </section>
            )}
          </div>
        ) : (
          <EmptyState message="Failed to load alert details." />
        )}
      </DetailDrawer>
    </div>
  );
}