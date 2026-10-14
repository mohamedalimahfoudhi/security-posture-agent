import { useState, useEffect } from 'react';
import { getAssessments } from '../api/client';

const severityColors = {
  critical: '#E2483C',
  high: '#D65A3C',
  elevated: '#D9B23D',
  low: '#4C8C63',
};

function formatTimestamp(createdAt) {
  if (!createdAt) return 'unknown';
  const now = new Date();
  const diff = now - new Date(createdAt);
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);

  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  return `${days}d ago`;
}

function mapSeverity(severity) {
  const severityMap = {
    'CRITICAL': 'critical',
    'HIGH': 'high',
    'MEDIUM': 'elevated',
    'LOW': 'low'
  };
  return severityMap[severity] || 'low';
}

export default function LiveFindingsFeed() {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function loadFindings() {
      try {
        setLoading(true);
        const assessments = await getAssessments();
        
        // Transform assessments to findings format
        const transformedFindings = assessments.slice(0, 10).map(assessment => {
          // Parse evidence if available
          let matchedAsset = null;
          if (assessment.evidence) {
            try {
              const evidence = typeof assessment.evidence === 'string' 
                ? JSON.parse(assessment.evidence) 
                : assessment.evidence;
              
              if (evidence.source === 'asset_correlation') {
                matchedAsset = evidence;
              }
            } catch (e) {
              console.error('Failed to parse evidence:', e);
            }
          }

          return {
            id: assessment.id,
            severity: mapSeverity(assessment.severity),
            vendor: assessment.vendor || 'Unknown',
            threat_source: assessment.threat_source || 'Unknown',
            customer: assessment.customer || 'Unknown',
            cve: assessment.vulnerability || 'Unknown',
            riskScore: assessment.risk_score || 0,
            timestamp: formatTimestamp(assessment.created_at),
            matchedAsset: matchedAsset,
            confidence: assessment.confidence,
            threat_summary: assessment.threat_summary,
            affected_third_party: assessment.affected_third_party,
            ransomware_group: assessment.ransomware_group,
            hunting_guidance: Array.isArray(assessment.hunting_guidance)
              ? assessment.hunting_guidance
              : (assessment.hunting_guidance?.techniques?.map(t => t.hunting_guidance) || []),
            assessment_techniques: assessment.assessment_techniques || [],
            isIncidentPath: !assessment.vulnerability
          };
        });

        setFindings(transformedFindings);
        setError(null);
      } catch (err) {
        console.error('Failed to load findings:', err);
        setError('Failed to load data');
      } finally {
        setLoading(false);
      }
    }

    loadFindings();

    // Refresh every 30 seconds
    const interval = setInterval(loadFindings, 30000);
    return () => clearInterval(interval);
  }, []);

  // Calculate severity breakdown for the bar
  const severityCounts = findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, {});

  const total = findings.length || 1;
  const criticalPercent = ((severityCounts.critical || 0) / total) * 100;
  const highPercent = ((severityCounts.high || 0) / total) * 100;
  const elevatedPercent = ((severityCounts.elevated || 0) / total) * 100;
  const lowPercent = ((severityCounts.low || 0) / total) * 100;

  return (
    <div className="bg-panel border border-hairline rounded-lg p-4 h-full flex flex-col">
      <h3 className="text-base font-semibold font-display text-ink mb-4">LIVE FINDINGS</h3>
      
      {loading ? (
        <div className="flex-1 flex items-center justify-center">
          <span className="text-sm text-mist font-body">Loading...</span>
        </div>
      ) : error ? (
        <div className="flex-1 flex items-center justify-center">
          <span className="text-sm text-ember-bright font-body">{error}</span>
        </div>
      ) : findings.length === 0 ? (
        <div className="flex-1 flex items-center justify-center">
          <span className="text-sm text-mist font-body">No findings available</span>
        </div>
      ) : (
        <>
          {/* Severity breakdown bar */}
          <div className="h-2 rounded-full overflow-hidden mb-4 flex">
            <div 
              className="bg-sev-critical" 
              style={{ width: `${criticalPercent}%` }}
              title={`Critical: ${criticalPercent.toFixed(0)}%`}
            />
            <div 
              className="bg-sev-high" 
              style={{ width: `${highPercent}%` }}
              title={`High: ${highPercent.toFixed(0)}%`}
            />
            <div 
              className="bg-sev-elevated" 
              style={{ width: `${elevatedPercent}%` }}
              title={`Elevated: ${elevatedPercent.toFixed(0)}%`}
            />
            <div 
              className="bg-sev-low" 
              style={{ width: `${lowPercent}%` }}
              title={`Low: ${lowPercent.toFixed(0)}%`}
            />
          </div>

          {/* Findings list */}
          <div className="flex-1 overflow-y-auto space-y-2">
            {findings.map((finding, index) => (
              <div
                key={finding.id}
                className="p-3 bg-void rounded border-l-4 animate-slide-down"
                style={{ 
                  borderColor: severityColors[finding.severity],
                  animationDelay: `${index * 50}ms`,
                }}
              >
                <div className="flex items-center gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono font-bold px-1.5 py-0.5 rounded" style={{ color: severityColors[finding.severity], background: `${severityColors[finding.severity]}18`, border: `1px solid ${severityColors[finding.severity]}40` }}>
                        {finding.severity.toUpperCase()}
                      </span>
                      <span className="text-sm font-mono text-ink break-all">{finding.vendor}</span>
                      <span className="text-mist">·</span>
                      <span className="text-xs font-mono text-mist break-all">{finding.threat_source}</span>
                      <span className="text-mist">·</span>
                      <span className="text-sm font-mono text-ink break-all">{finding.customer}</span>
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      {finding.isIncidentPath ? (
                        <>
                          <span className="text-xs font-mono text-mist">
                            {finding.affected_third_party || 'Unknown third party'}
                          </span>
                          {finding.ransomware_group && (
                            <>
                              <span className="text-mist">·</span>
                              <span className="text-xs font-mono text-ember-bright">
                            ransomware: {finding.ransomware_group}
                          </span>
                            </>
                          )}
                        </>
                      ) : (
                        <span className="text-xs font-mono text-mist">{finding.cve}</span>
                      )}
                      <span className="text-mist">·</span>
                      <span className="text-xs font-mono text-ink">risk {finding.riskScore}</span>
                    </div>

                    {/* Threat Summary */}
                    {finding.threat_summary && (
                      <div className="mt-2 p-2 bg-panel rounded border border-hairline">
                        <p className="text-xs text-mist font-body line-clamp-3">
                          {finding.threat_summary}
                        </p>
                      </div>
                    )}

                    {/* Matched Asset Information */}
                    {finding.matchedAsset && (
                      <div className="mt-2 p-2 bg-panel rounded border border-hairline">
                        <div className="flex items-center gap-2 text-xs">
                          <span className="text-sev-low font-medium">Matched Asset:</span>
                          <span className="text-ink font-medium">{finding.matchedAsset.asset_technology}</span>
                          {finding.matchedAsset.asset_version && (
                            <span className="text-mist font-mono">v{finding.matchedAsset.asset_version}</span>
                          )}
                        </div>
                        <div className="flex items-center gap-4 mt-1 text-xs text-mist">
                          <span>Vendor: {finding.matchedAsset.asset_vendor || finding.vendor || 'Unknown'}</span>
                          <span>Confidence: {finding.confidence}%</span>
                          {finding.matchedAsset.internet_exposed && (
                            <span className="text-ember-bright">Internet Exposed</span>
                          )}
                          {finding.matchedAsset.sensitive_data && (
                            <span className="text-sev-elevated">Sensitive Data</span>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Hunting Guidance */}
                    {finding.hunting_guidance && finding.hunting_guidance.length > 0 && (
                      <div className="mt-2 p-2 bg-panel rounded border border-hairline">
                        <p className="text-xs font-semibold text-ink font-body mb-1">
                          Hunting Guidance
                        </p>
                        {finding.hunting_guidance.map((guidance, idx) => (
                          <p key={idx} className="text-xs text-mist font-body">
                            • {guidance}
                          </p>
                        ))}
                      </div>
                    )}

                    {/* MITRE ATT&CK Technique Tags */}
                    {finding.assessment_techniques && finding.assessment_techniques.length > 0 && (
                      <div className="mt-2 p-2 bg-panel rounded border border-hairline">
                        <p className="text-xs font-semibold text-ink font-body mb-1">
                          MITRE ATT&CK Techniques
                        </p>
                        <div className="flex flex-wrap gap-1">
                          {finding.assessment_techniques.map((tech) => (
                            <span
                              key={tech.technique_id}
                              className="text-xs font-mono bg-void px-2 py-1 rounded border border-hairline"
                              title={tech.name}
                            >
                              {tech.technique_id}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                  <span className="text-xs text-mist font-body whitespace-nowrap">{finding.timestamp}</span>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
