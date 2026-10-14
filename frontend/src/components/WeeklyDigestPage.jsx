import { useState, useEffect } from 'react';
import { getWeeklyDigest, regenerateWeeklyDigest } from '../api/client';
import { AlertTriangle, Shield, FileText, TrendingDown, Sparkles, RefreshCw, Target, Database, CheckCircle, Clock, AlertCircle } from 'lucide-react';

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

export default function WeeklyDigestPage() {
  const [digest, setDigest] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [regenerating, setRegenerating] = useState(false);
  const [userRole, setUserRole] = useState(null);

  useEffect(() => {
    loadDigest();
    const userStr = localStorage.getItem('user');
    if (userStr) {
      try {
        const user = JSON.parse(userStr);
        setUserRole(user.role || 'Viewer');
      } catch (e) {
        console.error('Failed to parse user data:', e);
      }
    }
  }, []);

  const loadDigest = async () => {
    try {
      setLoading(true);
      const data = await getWeeklyDigest();
      setDigest(data);
      setError(null);
    } catch (err) {
      console.error('Failed to load weekly digest:', err);
      setError('Failed to load weekly digest');
    } finally {
      setLoading(false);
    }
  };

  const handleRegenerate = async () => {
    try {
      setRegenerating(true);
      const data = await regenerateWeeklyDigest();
      setDigest(data);
    } catch (err) {
      console.error('Failed to regenerate digest:', err);
      setError('Failed to regenerate digest');
    } finally {
      setRegenerating(false);
    }
  };

  const formatDate = (iso) => {
    if (!iso) return 'Unknown';
    return new Date(iso).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center">
          <FileText className="w-12 h-12 text-mist mx-auto mb-4 animate-pulse" />
          <p className="text-sm text-mist">Loading weekly digest...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center">
          <AlertCircle className="w-12 h-12 text-ember-bright mx-auto mb-4" />
          <p className="text-sm text-ink mb-2">{error}</p>
          <button onClick={loadDigest} className="text-xs text-ember-bright hover:underline">Retry</button>
        </div>
      </div>
    );
  }

  if (!digest) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center">
          <FileText className="w-12 h-12 text-mist mx-auto mb-4" />
          <p className="text-sm text-mist">No digest data available</p>
          <p className="text-xs text-mist mt-2">Generate your first weekly digest to see intelligence summary</p>
        </div>
      </div>
    );
  }

  const { period, overall_risk, risk_change, critical_vendors, high_risk_vendors, new_alerts, resolved_alerts, new_vulnerabilities, new_breaches, new_ransomware_events, architecture_changes, new_external_exposures, top_risks, recommendations, ai_summary } = digest;

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <div>
            <h1 className="text-2xl font-semibold text-ink font-display">WEEKLY THREAT INTELLIGENCE DIGEST</h1>
            <p className="text-sm text-mist mt-1">
              Week of {formatDate(period?.start)} – {formatDate(period?.end)}
            </p>
          </div>
          {userRole === 'Admin' && (
            <button
              onClick={handleRegenerate}
              disabled={regenerating}
              className="flex items-center gap-2 px-4 py-2 text-xs font-medium text-ink bg-void border border-hairline rounded hover:bg-ember-dim transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${regenerating ? 'animate-spin' : ''}`} />
              {regenerating ? 'Regenerating...' : 'Regenerate AI Analysis'}
            </button>
          )}
        </div>
      </div>

      {/* Summary Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 mb-6">
        <div className="bg-panel border border-hairline rounded-lg p-4">
          <p className="text-xs text-mist mb-1">NEW THREATS</p>
          <p className="text-2xl font-bold text-ink">{new_vulnerabilities || 0}</p>
        </div>
        <div className="bg-panel border border-hairline rounded-lg p-4">
          <p className="text-xs text-mist mb-1">NEW ALERTS</p>
          <p className="text-2xl font-bold text-ink">{new_alerts || 0}</p>
        </div>
        <div className="bg-panel border border-hairline rounded-lg p-4">
          <p className="text-xs text-mist mb-1">NEW EXPOSURES</p>
          <p className="text-2xl font-bold text-ink">{new_external_exposures || 0}</p>
        </div>
        <div className="bg-panel border border-hairline rounded-lg p-4">
          <p className="text-xs text-mist mb-1">NEW BREACHES</p>
          <p className="text-2xl font-bold text-ink">{new_breaches || 0}</p>
        </div>
        <div className="bg-panel border border-hairline rounded-lg p-4">
          <p className="text-xs text-mist mb-1">CRITICAL ITEMS</p>
          <p className="text-2xl font-bold text-sev-critical">{critical_vendors?.length || 0}</p>
        </div>
        <div className="bg-panel border border-hairline rounded-lg p-4">
          <p className="text-xs text-mist mb-1">AFFECTED VENDORS</p>
          <p className="text-2xl font-bold text-ink">{(critical_vendors?.length || 0) + (high_risk_vendors?.length || 0)}</p>
        </div>
      </div>

      {/* AI Executive Summary */}
      {ai_summary ? (
        <div className="bg-void border border-ember-dim/30 rounded-lg p-6 mb-6">
          <div className="flex items-center gap-2 mb-4">
            <Sparkles className="w-5 h-5 text-ember-bright" />
            <h2 className="text-lg font-semibold text-ink font-display">EXECUTIVE SUMMARY</h2>
            {ai_summary.generated_at && (
              <span className="text-xs text-mist ml-auto">
                Generated {formatDate(ai_summary.generated_at)}
              </span>
            )}
          </div>
          <p className="text-sm text-ink leading-relaxed mb-4">
            {ai_summary.executive_summary || 'No executive summary available.'}
          </p>
          {ai_summary.recommendations && ai_summary.recommendations.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-ink mb-2">KEY RECOMMENDATIONS</h3>
              <ul className="space-y-2">
                {ai_summary.recommendations.map((rec, idx) => (
                  <li key={idx} className="text-sm text-ink flex items-start gap-2">
                    <span className="text-ember-bright font-mono">{idx + 1}.</span>
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {ai_summary.future_outlook && (
            <div className="mt-4 pt-4 border-t border-hairline">
              <h3 className="text-sm font-semibold text-ink mb-2">LOOKING AHEAD</h3>
              <p className="text-sm text-ink">{ai_summary.future_outlook}</p>
            </div>
          )}
        </div>
      ) : (
        <div className="bg-void border border-hairline rounded-lg p-6 mb-6">
          <div className="flex items-center gap-2 mb-2">
            <Sparkles className="w-5 h-5 text-mist" />
            <h2 className="text-lg font-semibold text-mist font-display">AI SUMMARY UNAVAILABLE</h2>
          </div>
          <p className="text-sm text-mist">
            AI analysis is currently unavailable. The digest below shows real database intelligence.
          </p>
        </div>
      )}

      {/* Attack & Threat Analysis */}
      {(new_breaches > 0 || new_ransomware_events > 0) && (
        <div className="bg-panel border border-hairline rounded-lg p-6 mb-6">
          <div className="flex items-center gap-2 mb-4">
            <Target className="w-5 h-5 text-ember-bright" />
            <h2 className="text-lg font-semibold text-ink font-display">ATTACK & THREAT ANALYSIS</h2>
          </div>
          {new_breaches > 0 && (
            <div className="mb-4">
              <p className="text-sm text-ink mb-2"><strong>{new_breaches}</strong> new data breaches detected this week affecting customer ecosystem.</p>
            </div>
          )}
          {new_ransomware_events > 0 && (
            <div className="mb-4">
              <p className="text-sm text-ink mb-2"><strong>{new_ransomware_events}</strong> ransomware events detected this week.</p>
            </div>
          )}
        </div>
      )}

      {/* Affected Technologies */}
      {top_risks && top_risks.length > 0 && (
        <div className="bg-panel border border-hairline rounded-lg p-6 mb-6">
          <div className="flex items-center gap-2 mb-4">
            <Database className="w-5 h-5 text-viz-teal" />
            <h2 className="text-lg font-semibold text-ink font-display">AFFECTED TECHNOLOGIES</h2>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-hairline">
                <th className="text-left text-xs font-semibold text-mist uppercase tracking-wider py-2">Technology</th>
                <th className="text-left text-xs font-semibold text-mist uppercase tracking-wider py-2">Vendor</th>
                <th className="text-left text-xs font-semibold text-mist uppercase tracking-wider py-2">Risk</th>
                <th className="text-left text-xs font-semibold text-mist uppercase tracking-wider py-2">Reason</th>
              </tr>
            </thead>
            <tbody>
              {top_risks.map((risk, idx) => (
                <tr key={idx} className="border-b border-hairline/50 last:border-0">
                  <td className="py-3 text-sm text-ink">{risk.technologies || risk.business_role || '—'}</td>
                  <td className="py-3 text-sm text-ink">{risk.vendor}</td>
                  <td className="py-3">
                    <span className="text-xs px-2 py-1 rounded border font-semibold" style={getSeverityStyle(risk.risk_score > 75 ? 'HIGH' : risk.risk_score > 50 ? 'MEDIUM' : 'LOW')}>
                      {risk.risk_score}
                    </span>
                  </td>
                  <td className="py-3 text-xs text-mist">{risk.alert_type || 'Vulnerability'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Recommended Actions */}
      {recommendations && recommendations.length > 0 && (
        <div className="bg-panel border border-hairline rounded-lg p-6 mb-6">
          <div className="flex items-center gap-2 mb-4">
            <CheckCircle className="w-5 h-5 text-sev-low" />
            <h2 className="text-lg font-semibold text-ink font-display">RECOMMENDED ACTIONS</h2>
          </div>
          <div className="space-y-4">
            {recommendations.map((rec, idx) => (
              <div key={idx} className="bg-void border border-hairline rounded-lg p-4">
                <div className="flex items-start justify-between mb-2">
                  <h3 className="text-sm font-semibold text-ink">{rec.action}</h3>
                  <span className="text-xs px-2 py-1 rounded border font-semibold" style={getSeverityStyle(rec.priority || 'MEDIUM')}>
                    {rec.priority || 'MEDIUM'}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-4 mb-3">
                  <div>
                    <p className="text-xs text-mist mb-1">Affected Technology</p>
                    <p className="text-sm text-ink">{rec.technology || rec.vendor || '—'}</p>
                  </div>
                  <div>
                    <p className="text-xs text-mist mb-1">Vendor</p>
                    <p className="text-sm text-ink">{rec.vendor}</p>
                  </div>
                </div>
                <div className="mb-3">
                  <p className="text-xs text-mist mb-1">Impact</p>
                  <p className="text-sm text-ink">{rec.impact || '—'}</p>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-mist">Alert Type: {rec.alert_type}</span>
                  <span className="text-xs px-2 py-1 rounded bg-sev-low/20 text-sev-low">
                    {rec.status || 'NOT CHECKED'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Critical & High Risk Vendors */}
      {(critical_vendors?.length > 0 || high_risk_vendors?.length > 0) && (
        <div className="bg-panel border border-hairline rounded-lg p-6 mb-6">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-5 h-5 text-ember-bright" />
            <h2 className="text-lg font-semibold text-ink font-display">HIGH-RISK VENDORS</h2>
          </div>
          <div className="space-y-2">
            {critical_vendors?.map((vendor, idx) => (
              <div key={idx} className="flex items-center justify-between p-3 bg-void border border-hairline rounded">
                <div className="flex items-center gap-3">
                  <span className="text-sm font-medium text-ink">{vendor.vendor}</span>
                  <span className="text-xs px-2 py-1 rounded bg-sev-critical/20 text-sev-critical font-semibold">CRITICAL</span>
                </div>
                <span className="text-sm font-mono text-ink">{vendor.risk_score}</span>
              </div>
            ))}
            {high_risk_vendors?.map((vendor, idx) => (
              <div key={idx} className="flex items-center justify-between p-3 bg-void border border-hairline rounded">
                <div className="flex items-center gap-3">
                  <span className="text-sm font-medium text-ink">{vendor.vendor}</span>
                  <span className="text-xs px-2 py-1 rounded bg-sev-high/20 text-sev-high font-semibold">HIGH</span>
                </div>
                <span className="text-sm font-mono text-ink">{vendor.risk_score}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* No Data State */}
      {(!ai_summary && (!top_risks || top_risks.length === 0) && (!recommendations || recommendations.length === 0) && (!critical_vendors || critical_vendors.length === 0) && (!high_risk_vendors || high_risk_vendors.length === 0)) && (
        <div className="bg-panel border border-hairline rounded-lg p-12 text-center">
          <Clock className="w-12 h-12 text-mist mx-auto mb-4" />
          <p className="text-sm text-ink mb-2">No significant findings this week</p>
          <p className="text-xs text-mist">Your security posture remains stable. Continue monitoring for new threats.</p>
        </div>
      )}
    </div>
  );
}
