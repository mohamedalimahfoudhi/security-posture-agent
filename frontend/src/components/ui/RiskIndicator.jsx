import React from 'react';

export default function RiskIndicator({ score, showLabel = false }) {
  if (score === null || score === undefined) {
    return <span className="text-mist text-xs font-mono">--</span>;
  }
  
  let color = 'text-mist';
  if (score >= 90) color = 'text-sev-critical';
  else if (score >= 70) color = 'text-sev-high';
  else if (score >= 40) color = 'text-sev-elevated';
  else if (score > 0) color = 'text-sev-low';
  
  return (
    <div className="flex items-center gap-1.5">
      <span className={`font-mono font-bold ${color}`}>
        {score}
      </span>
      {showLabel && <span className="text-[10px] text-mist font-medium">RISK</span>}
    </div>
  );
}
