import React from 'react';

export default function SeverityDistribution({ items, severityField = 'severity' }) {
  if (!items || items.length === 0) {
    return (
      <div className="border border-hairline rounded-lg bg-[#0D0F11] p-4">
        <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-4">SEVERITY DISTRIBUTION</h3>
        <p className="text-xs text-mist">No data available</p>
      </div>
    );
  }

  const severityDist = {
    CRITICAL: items.filter(i => i[severityField] === 'CRITICAL').length,
    HIGH: items.filter(i => i[severityField] === 'HIGH').length,
    MEDIUM: items.filter(i => i[severityField] === 'MEDIUM').length,
    LOW: items.filter(i => i[severityField] === 'LOW').length,
  };

  const total = items.length;
  const maxCount = Math.max(...Object.values(severityDist), 1);

  const severityConfig = [
    { label: 'CRITICAL', count: severityDist.CRITICAL, color: 'bg-sev-critical' },
    { label: 'HIGH', count: severityDist.HIGH, color: 'bg-sev-high' },
    { label: 'MEDIUM', count: severityDist.MEDIUM, color: 'bg-sev-elevated' },
    { label: 'LOW', count: severityDist.LOW, color: 'bg-sev-low' }
  ];

  return (
    <div className="border border-hairline rounded-lg bg-[#0D0F11] p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xs font-semibold text-ink uppercase tracking-wider">SEVERITY DISTRIBUTION</h3>
        <span className="text-[10px] text-mist">{total} TOTAL</span>
      </div>
      
      <div className="space-y-2">
        {severityConfig.map(s => (
          <div key={s.label} className="flex items-center gap-3">
            <span className="text-[10px] font-semibold text-mist w-14">{s.label}</span>
            <div className="flex-1 h-3 bg-void rounded overflow-hidden">
              <div 
                className={`h-full ${s.color} transition-all`}
                style={{ width: `${Math.max(4, (s.count / maxCount) * 100)}%` }}
              />
            </div>
            <span className="text-xs font-mono text-ink w-8 text-right">{s.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
