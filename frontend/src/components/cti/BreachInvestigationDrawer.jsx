import React from 'react';
import { X, Building2, Database, AlertTriangle, Shield, ExternalLink, Target, Clock } from 'lucide-react';
import SeverityBadge from '../ui/SeverityBadge';
import RiskIndicator from '../ui/RiskIndicator';
import StatusBadge from '../ui/StatusBadge';

const SEV_COLOURS = {
  CRITICAL: '#E2483C',
  HIGH: '#D65A3C',
  MEDIUM: '#D9B23D',
  LOW: '#4C8C63',
  UNKNOWN: '#6B7280',
};

function getSeverityStyle(severity) {
  const colour = SEV_COLOURS[severity] || SEV_COLOURS.UNKNOWN;
  return { backgroundColor: `${colour}1A`, borderColor: `${colour}4D`, color: colour };
}

export default function BreachInvestigationDrawer({ breach, onClose }) {
  if (!breach) return null;

  return (
    <div className="fixed inset-0 z-50 flex">
      <div className="flex-1 bg-black/50" onClick={onClose} />
      <div className="w-[800px] bg-[#0D0F11] border-l border-hairline flex flex-col h-full">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-hairline bg-void/30">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-sev-critical" />
            <div>
              <h2 className="text-sm font-semibold text-ink">{breach.title}</h2>
              <p className="text-[10px] text-mist font-mono">ID: {breach.id}</p>
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
              <p className="text-[9px] text-mist uppercase tracking-wider">Severity</p>
              <span className="text-xs px-2 py-1 rounded border font-semibold" style={getSeverityStyle(breach.severity)}>
                {breach.severity}
              </span>
            </div>
            <div>
              <p className="text-[9px] text-mist uppercase tracking-wider">Risk</p>
              <RiskIndicator score={breach.risk_score} showLabel />
            </div>
            <div>
              <p className="text-[9px] text-mist uppercase tracking-wider">Status</p>
              <StatusBadge status={breach.status} />
            </div>
            <div>
              <p className="text-[9px] text-mist uppercase tracking-wider">Published</p>
              <span className="text-xs font-mono text-ink">
                {breach.published_at ? new Date(breach.published_at).toISOString().split('T')[0] : '—'}
              </span>
            </div>
            <div>
              <p className="text-[9px] text-mist uppercase tracking-wider">Confidence</p>
              <span className="text-xs font-mono text-ink">
                {breach.confidence ? `${Math.round(breach.confidence * 100)}%` : '—'}
              </span>
            </div>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-6 space-y-6">
          {/* Incident Overview */}
          <div>
            <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-3">INCIDENT OVERVIEW</h3>
            <div className="bg-void border border-hairline rounded p-4 space-y-3">
              {breach.description && (
                <div>
                  <p className="text-[10px] text-mist uppercase tracking-wider mb-1">Description</p>
                  <p className="text-sm text-ink">{breach.description}</p>
                </div>
              )}
              {breach.alert_type && (
                <div>
                  <p className="text-[10px] text-mist uppercase tracking-wider mb-1">Incident Type</p>
                  <span className="text-xs font-mono text-ink bg-[#0D0F11] px-2 py-1 rounded border border-hairline">
                    {breach.alert_type}
                  </span>
                </div>
              )}
              {breach.source_url && (
                <div>
                  <a
                    href={breach.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 text-xs text-viz-blue hover:underline"
                  >
                    <ExternalLink className="w-3 h-3" />
                    View Source
                  </a>
                </div>
              )}
            </div>
          </div>

          {/* Why This Matters */}
          {breach.customer_impact && (
            <div>
              <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-3">WHY THIS MATTERS TO THE CUSTOMER</h3>
              <div className="bg-void border border-hairline rounded p-4">
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Building2 className="w-4 h-4 text-viz-blue" />
                    <div>
                      <p className="text-[10px] text-mist uppercase">Vendor</p>
                      <span className="text-xs text-ink">{breach.vendor_name || '—'}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Database className="w-4 h-4 text-viz-teal" />
                    <div>
                      <p className="text-[10px] text-mist uppercase">Affected Technology</p>
                      <span className="text-xs text-ink">{breach.technology_name || '—'}</span>
                    </div>
                  </div>
                  {breach.match_reason && (
                    <div className="pt-3 border-t border-hairline">
                      <p className="text-[10px] text-mist uppercase tracking-wider mb-1">Match Reason</p>
                      <p className="text-xs text-ink">{breach.match_reason}</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Customer Exposure */}
          <div>
            <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-3">CUSTOMER EXPOSURE</h3>
            <div className="bg-void border border-hairline rounded p-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-[10px] text-mist uppercase tracking-wider mb-1">Exposure</p>
                  <span className={`text-xs font-semibold ${breach.customer_impact ? 'text-sev-critical' : 'text-sev-low'}`}>
                    {breach.customer_impact ? 'DIRECT' : 'NO EXPOSURE'}
                  </span>
                </div>
                <div>
                  <p className="text-[10px] text-mist uppercase tracking-wider mb-1">Risk Score</p>
                  <RiskIndicator score={breach.risk_score} showLabel />
                </div>
              </div>
              {breach.business_relevance && (
                <div className="mt-3 pt-3 border-t border-hairline">
                  <p className="text-[10px] text-mist uppercase tracking-wider mb-1">Business Relevance</p>
                  <p className="text-sm text-ink">{breach.business_relevance}</p>
                </div>
              )}
            </div>
          </div>

          {/* Threat Intelligence */}
          <div>
            <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-3">THREAT INTELLIGENCE</h3>
            <div className="bg-void border border-hairline rounded p-4 space-y-3">
              {breach.evidence && Array.isArray(breach.evidence) && breach.evidence.length > 0 && (
                <div>
                  <p className="text-[10px] text-mist uppercase tracking-wider mb-1">Evidence</p>
                  <div className="text-xs text-ink bg-[#0D0F11] p-2 rounded border border-hairline space-y-1">
                    {breach.evidence.map((e, idx) => (
                      <div key={idx}>• {typeof e === 'string' ? e : JSON.stringify(e)}</div>
                    ))}
                  </div>
                </div>
              )}
              {breach.confidence_reasons && breach.confidence_reasons.length > 0 && (
                <div>
                  <p className="text-[10px] text-mist uppercase tracking-wider mb-1">Confidence Factors</p>
                  <div className="space-y-1">
                    {breach.confidence_reasons.map((reason, idx) => (
                      <p key={idx} className="text-xs text-ink">• {reason}</p>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Recommended Response */}
          {breach.recommended_action && (
            <div>
              <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-3">RECOMMENDED RESPONSE</h3>
              <div className="bg-void border border-hairline rounded p-4">
                <div className="text-sm text-ink space-y-2">
                  {breach.recommended_action.split('\n').map((line, idx) => (
                    <div key={idx} className="flex items-start gap-2">
                      <span className="text-ember-bright font-mono">{idx + 1}.</span>
                      <span>{line}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Status */}
          <div>
            <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-3">STATUS</h3>
            <div className="bg-void border border-hairline rounded p-4">
              <div className="flex items-center justify-between">
                <StatusBadge status={breach.status} />
                <div className="flex items-center gap-2 text-[10px] text-mist">
                  <Clock className="w-3 h-3" />
                  <span className="font-mono">
                    {breach.created_at ? new Date(breach.created_at).toISOString().split('T')[0] : '—'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
