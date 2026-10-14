import { useState, useEffect } from 'react';
import { Database, AlertCircle } from 'lucide-react';
import { getDetectedTechnologies } from '../api/client';

const severityColors = {
  CRITICAL: 'bg-sev-critical',
  HIGH: 'bg-sev-high',
  MEDIUM: 'bg-sev-elevated',
  LOW: 'bg-sev-low',
};

export default function DetectedTechnologies() {
  const [technologies, setTechnologies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function loadTechnologies() {
      try {
        setLoading(true);
        const data = await getDetectedTechnologies();
        setTechnologies(data.technologies || []);
        setError(null);
      } catch (err) {
        console.error('Failed to load detected technologies:', err);
        setError('Failed to load data');
      } finally {
        setLoading(false);
      }
    }

    loadTechnologies();
  }, []);

  if (loading) {
    return (
      <div className="bg-panel border border-hairline rounded-lg p-4 h-full flex flex-col">
        <h3 className="text-base font-semibold font-display text-ink mb-4">DETECTED TECHNOLOGIES</h3>
        <div className="flex-1 flex items-center justify-center">
          <span className="text-sm text-mist font-body">Loading...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-panel border border-hairline rounded-lg p-4 h-full flex flex-col">
        <h3 className="text-base font-semibold font-display text-ink mb-4">DETECTED TECHNOLOGIES</h3>
        <div className="flex-1 flex items-center justify-center">
          <span className="text-sm text-ember-bright font-body">{error}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-panel border border-hairline rounded-lg p-4 h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-base font-semibold font-display text-ink">DETECTED TECHNOLOGIES</h3>
        <span className="text-xs text-mist font-body">{technologies.length} technologies</span>
      </div>

      {technologies.length === 0 ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <Database className="w-8 h-8 text-mist mx-auto mb-2" />
            <p className="text-sm text-mist font-body">No technologies detected</p>
            <p className="text-xs text-mist font-body mt-1">Upload documents to extract technologies</p>
          </div>
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto space-y-2">
          {technologies.slice(0, 10).map((tech, index) => (
            <div
              key={index}
              className="flex items-center gap-3 p-2 bg-void rounded border-l-2"
              style={{
                borderColor: tech.criticality === 'CRITICAL' ? '#E2483C' :
                           tech.criticality === 'HIGH' ? '#D65A3C' :
                           tech.criticality === 'MEDIUM' ? '#D9B23D' : '#4C8C63'
              }}
            >
              <Database className="w-4 h-4 text-mist" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-ink truncate">{tech.technology}</span>
                  {tech.version && (
                    <span className="text-xs text-mist font-mono">v{tech.version}</span>
                  )}
                </div>
                {tech.vendor && (
                  <div className="text-xs text-mist truncate">{tech.vendor}</div>
                )}
              </div>
              <span
                className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
                  severityColors[tech.criticality] || severityColors.MEDIUM
                } text-void`}
              >
                {tech.criticality}
              </span>
            </div>
          ))}
          
          {technologies.length > 10 && (
            <div className="text-center pt-2">
              <span className="text-xs text-mist font-body">
                +{technologies.length - 10} more technologies
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
