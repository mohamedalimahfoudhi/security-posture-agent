import React, { useState } from 'react';
import { X, Building2, Database, AlertTriangle, Shield, ExternalLink, ChevronDown, ChevronRight } from 'lucide-react';
import SeverityBadge from '../ui/SeverityBadge';
import RiskIndicator from '../ui/RiskIndicator';
import StatusBadge from '../ui/StatusBadge';

export default function VendorInvestigationDrawer({ vendor, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');

  if (!vendor) return null;

  const tabs = [
    { id: 'overview', label: 'OVERVIEW' },
    { id: 'architecture', label: 'ARCHITECTURE' },
    { id: 'technologies', label: 'TECHNOLOGIES' },
    { id: 'exposures', label: 'EXPOSURES' },
    { id: 'alerts', label: 'ALERTS' },
    { id: 'breaches', label: 'BREACHES' },
  ];

  return (
    <div className="fixed inset-0 z-50 flex">
      <div className="flex-1 bg-black/50" onClick={onClose} />
      <div className="w-[800px] bg-[#0D0F11] border-l border-hairline flex flex-col h-full">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-hairline bg-void/30">
          <div className="flex items-center gap-3">
            <Building2 className="w-5 h-5 text-viz-blue" />
            <div>
              <h2 className="text-sm font-semibold text-ink">{vendor.vendor}</h2>
              <p className="text-[10px] text-mist font-mono">ID: {vendor.id}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-mist hover:text-ink">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Quick Stats */}
        <div className="px-6 py-3 border-b border-hairline bg-void/20">
          <div className="flex items-center gap-6">
            <div>
              <p className="text-[9px] text-mist uppercase tracking-wider">Criticality</p>
              <SeverityBadge severity={vendor.criticality} />
            </div>
            <div>
              <p className="text-[9px] text-mist uppercase tracking-wider">Risk</p>
              <RiskIndicator score={vendor.risk_score} showLabel />
            </div>
            <div>
              <p className="text-[9px] text-mist uppercase tracking-wider">Technologies</p>
              <span className="text-xs font-mono text-ink">{vendor.technology_count || 0}</span>
            </div>
            <div>
              <p className="text-[9px] text-mist uppercase tracking-wider">Exposures</p>
              <span className="text-xs font-mono text-sev-critical">{vendor.exposures_count || 0}</span>
            </div>
            <div>
              <p className="text-[9px] text-mist uppercase tracking-wider">Alerts</p>
              <span className="text-xs font-mono text-ember-bright">{vendor.alerts_count || 0}</span>
            </div>
            <div>
              <p className="text-[9px] text-mist uppercase tracking-wider">Breaches</p>
              <span className="text-xs font-mono text-ink">{vendor.breaches_count || 0}</span>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-hairline bg-void/30">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 text-[10px] font-semibold uppercase tracking-wider border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-viz-blue text-ink'
                  : 'border-transparent text-mist hover:text-ink'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-6">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-3">WHY THIS VENDOR MATTERS</h3>
                <div className="bg-void border border-hairline rounded p-4">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-mist uppercase">Business Criticality</span>
                      <SeverityBadge severity={vendor.criticality} />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-mist uppercase">Security Risk</span>
                      <RiskIndicator score={vendor.risk_score} showLabel />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-mist uppercase">Technology Dependencies</span>
                      <span className="text-xs font-mono text-ink">{vendor.technology_count || 0}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-mist uppercase">Active Exposures</span>
                      <span className="text-xs font-mono text-sev-critical">{vendor.exposures_count || 0}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-mist uppercase">Active Alerts</span>
                      <span className="text-xs font-mono text-ember-bright">{vendor.alerts_count || 0}</span>
                    </div>
                  </div>
                </div>
              </div>

              {vendor.business_relevance && (
                <div>
                  <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-3">BUSINESS RELEVANCE</h3>
                  <div className="bg-void border border-hairline rounded p-4">
                    <p className="text-sm text-ink">{vendor.business_relevance}</p>
                  </div>
                </div>
              )}

              <div>
                <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-3">RISK FACTORS</h3>
                <div className="bg-void border border-hairline rounded p-4">
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-sev-critical" />
                      <span className="text-xs text-ink">{vendor.exposures_count || 0} active exposures</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Shield className="w-4 h-4 text-ember-bright" />
                      <span className="text-xs text-ink">{vendor.alerts_count || 0} active alerts</span>
                    </div>
                    {vendor.breaches_count > 0 && (
                      <div className="flex items-center gap-2">
                        <Database className="w-4 h-4 text-viz-blue" />
                        <span className="text-xs text-ink">{vendor.breaches_count} relevant breaches</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'architecture' && (
            <div className="space-y-4">
              <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-3">ARCHITECTURE DEPENDENCIES</h3>
              {vendor.technologies && vendor.technologies.length > 0 ? (
                <div className="bg-void border border-hairline rounded p-4">
                  <div className="space-y-2">
                    {vendor.technologies.map((tech, idx) => (
                      <div key={idx} className="flex items-center gap-2 p-2 bg-[#0D0F11] border border-hairline rounded">
                        <Database className="w-3 h-3 text-viz-teal" />
                        <span className="text-xs text-ink">{tech.technology || tech}</span>
                        {tech.category && (
                          <span className="text-[10px] text-mist ml-auto">{tech.category}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <p className="text-xs text-mist">No architecture data available</p>
              )}
            </div>
          )}

          {activeTab === 'technologies' && (
            <div className="space-y-4">
              <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-3">TECHNOLOGIES</h3>
              {vendor.technologies && vendor.technologies.length > 0 ? (
                <div className="border border-hairline rounded bg-[#0D0F11] overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-hairline bg-void/50">
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Technology</th>
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Category</th>
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Exposures</th>
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Alerts</th>
                      </tr>
                    </thead>
                    <tbody>
                      {vendor.technologies.map((tech, idx) => (
                        <tr key={idx} className="border-b border-hairline/50 last:border-0">
                          <td className="px-3 py-2 text-xs text-ink">{tech.technology || tech}</td>
                          <td className="px-3 py-2 text-[10px] text-mist">{tech.category || '—'}</td>
                          <td className="px-3 py-2 text-xs font-mono text-sev-critical">{tech.exposures_count || 0}</td>
                          <td className="px-3 py-2 text-xs font-mono text-ember-bright">{tech.alerts_count || 0}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-xs text-mist">No technologies recorded</p>
              )}
            </div>
          )}

          {activeTab === 'exposures' && (
            <div className="space-y-4">
              <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-3">EXPOSURES</h3>
              {vendor.exposures && vendor.exposures.length > 0 ? (
                <div className="border border-hairline rounded bg-[#0D0F11] overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-hairline bg-void/50">
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Technology</th>
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">CVE/Threat</th>
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Severity</th>
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Risk</th>
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {vendor.exposures.map((exp, idx) => (
                        <tr key={idx} className="border-b border-hairline/50 last:border-0">
                          <td className="px-3 py-2 text-xs text-ink">{exp.technology || '—'}</td>
                          <td className="px-3 py-2 text-xs font-mono text-ink">{exp.cve_id || exp.threat_title || '—'}</td>
                          <td className="px-3 py-2"><SeverityBadge severity={exp.severity} /></td>
                          <td className="px-3 py-2"><RiskIndicator score={exp.risk_score} /></td>
                          <td className="px-3 py-2"><StatusBadge status={exp.status} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-xs text-mist">No active exposures</p>
              )}
            </div>
          )}

          {activeTab === 'alerts' && (
            <div className="space-y-4">
              <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-3">ALERTS</h3>
              {vendor.alerts && vendor.alerts.length > 0 ? (
                <div className="border border-hairline rounded bg-[#0D0F11] overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-hairline bg-void/50">
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Severity</th>
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Type</th>
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Technology</th>
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Risk</th>
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {vendor.alerts.map((alert, idx) => (
                        <tr key={idx} className="border-b border-hairline/50 last:border-0">
                          <td className="px-3 py-2"><SeverityBadge severity={alert.severity} /></td>
                          <td className="px-3 py-2 text-[10px] text-ink uppercase">{alert.alert_type}</td>
                          <td className="px-3 py-2 text-xs text-ink">{alert.affected_technology || '—'}</td>
                          <td className="px-3 py-2"><RiskIndicator score={alert.risk_score} /></td>
                          <td className="px-3 py-2"><StatusBadge status={alert.status} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-xs text-mist">No active alerts</p>
              )}
            </div>
          )}

          {activeTab === 'breaches' && (
            <div className="space-y-4">
              <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-3">RELEVANT BREACHES</h3>
              {vendor.breaches && vendor.breaches.length > 0 ? (
                <div className="border border-hairline rounded bg-[#0D0F11] overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-hairline bg-void/50">
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Severity</th>
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Breach</th>
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Technology</th>
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Risk</th>
                        <th className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">Published</th>
                      </tr>
                    </thead>
                    <tbody>
                      {vendor.breaches.map((breach, idx) => (
                        <tr key={idx} className="border-b border-hairline/50 last:border-0">
                          <td className="px-3 py-2"><SeverityBadge severity={breach.severity} /></td>
                          <td className="px-3 py-2 text-xs text-ink">{breach.title}</td>
                          <td className="px-3 py-2 text-xs text-ink">{breach.technology_name || '—'}</td>
                          <td className="px-3 py-2"><RiskIndicator score={breach.risk_score} /></td>
                          <td className="px-3 py-2 text-[10px] text-mist font-mono">
                            {breach.published_at ? new Date(breach.published_at).toISOString().split('T')[0] : '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-xs text-mist">No relevant breaches</p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
