import React from 'react';
import { Building2 } from 'lucide-react';

const CRITICALITY_ORDER = { 'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0, 'UNKNOWN': 0 };

export default function RiskMatrix({ vendors, onVendorClick }) {
  // Group vendors by criticality and risk score
  const getCriticalityValue = (c) => CRITICALITY_ORDER[c?.toUpperCase()] || 0;
  
  const matrixData = [
    { label: 'CRITICAL / HIGH RISK', vendors: vendors.filter(v => getCriticalityValue(v.criticality) === 3 && (v.risk_score || 0) >= 70), color: 'bg-sev-critical' },
    { label: 'CRITICAL / MED RISK', vendors: vendors.filter(v => getCriticalityValue(v.criticality) === 3 && (v.risk_score || 0) >= 40 && (v.risk_score || 0) < 70), color: 'bg-sev-high' },
    { label: 'CRITICAL / LOW RISK', vendors: vendors.filter(v => getCriticalityValue(v.criticality) === 3 && (v.risk_score || 0) < 40), color: 'bg-sev-elevated' },
    { label: 'HIGH / HIGH RISK', vendors: vendors.filter(v => getCriticalityValue(v.criticality) === 2 && (v.risk_score || 0) >= 70), color: 'bg-sev-high' },
    { label: 'HIGH / MED RISK', vendors: vendors.filter(v => getCriticalityValue(v.criticality) === 2 && (v.risk_score || 0) >= 40 && (v.risk_score || 0) < 70), color: 'bg-sev-elevated' },
    { label: 'HIGH / LOW RISK', vendors: vendors.filter(v => getCriticalityValue(v.criticality) === 2 && (v.risk_score || 0) < 40), color: 'bg-sev-low' },
    { label: 'MEDIUM / HIGH RISK', vendors: vendors.filter(v => getCriticalityValue(v.criticality) === 1 && (v.risk_score || 0) >= 70), color: 'bg-sev-elevated' },
    { label: 'MEDIUM / MED RISK', vendors: vendors.filter(v => getCriticalityValue(v.criticality) === 1 && (v.risk_score || 0) >= 40 && (v.risk_score || 0) < 70), color: 'bg-sev-low' },
    { label: 'MEDIUM / LOW RISK', vendors: vendors.filter(v => getCriticalityValue(v.criticality) === 1 && (v.risk_score || 0) < 40), color: 'bg-sev-low' },
    { label: 'LOW / HIGH RISK', vendors: vendors.filter(v => getCriticalityValue(v.criticality) === 0 && (v.risk_score || 0) >= 70), color: 'bg-sev-elevated' },
    { label: 'LOW / MED RISK', vendors: vendors.filter(v => getCriticalityValue(v.criticality) === 0 && (v.risk_score || 0) >= 40 && (v.risk_score || 0) < 70), color: 'bg-sev-low' },
    { label: 'LOW / LOW RISK', vendors: vendors.filter(v => getCriticalityValue(v.criticality) === 0 && (v.risk_score || 0) < 40), color: 'bg-sev-low' },
  ];

  const maxCount = Math.max(...matrixData.map(d => d.vendors.length), 1);

  return (
    <div className="border border-hairline rounded-lg bg-[#0D0F11] p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xs font-semibold text-ink uppercase tracking-wider">VENDOR RISK MATRIX</h3>
        <div className="flex items-center gap-4 text-[10px] text-mist">
          <span className="flex items-center gap-1"><span className="w-2 h-2 bg-sev-critical rounded"></span> CRITICAL</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 bg-sev-high rounded"></span> HIGH</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 bg-sev-elevated rounded"></span> MEDIUM</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 bg-sev-low rounded"></span> LOW</span>
        </div>
      </div>
      
      <div className="grid grid-cols-3 gap-1">
        {matrixData.map((cell, idx) => (
          <div
            key={idx}
            className={`${cell.color} border border-hairline/30 rounded p-2 cursor-pointer hover:opacity-80 transition-opacity`}
            onClick={() => cell.vendors.length > 0 && onVendorClick && cell.vendors[0]}
          >
            <div className="text-lg font-bold text-ink">{cell.vendors.length}</div>
            <div className="text-[9px] text-ink/70 uppercase font-semibold tracking-tight">{cell.label}</div>
          </div>
        ))}
      </div>

      {/* Vendor list for selected cell */}
      <div className="mt-4 pt-4 border-t border-hairline">
        <h4 className="text-[10px] text-mist uppercase font-semibold mb-2">HIGH-RISK VENDORS</h4>
        <div className="space-y-1 max-h-32 overflow-auto">
          {vendors
            .filter(v => (v.risk_score || 0) >= 70)
            .slice(0, 8)
            .map(v => (
              <div
                key={v.id}
                onClick={() => onVendorClick && onVendorClick(v)}
                className="flex items-center justify-between p-2 bg-void border border-hairline rounded hover:border-viz-blue/50 cursor-pointer transition-colors"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <Building2 className="w-3 h-3 text-viz-blue shrink-0" />
                  <span className="text-xs font-medium text-ink truncate">{v.vendor}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[10px] text-mist font-mono">{v.risk_score || 0}</span>
                  <span className={`text-[9px] px-1.5 py-0.5 rounded font-semibold ${
                    v.criticality === 'CRITICAL' ? 'bg-sev-critical/20 text-sev-critical' :
                    v.criticality === 'HIGH' ? 'bg-sev-high/20 text-sev-high' :
                    'bg-sev-elevated/20 text-sev-elevated'
                  }`}>
                    {v.criticality || 'LOW'}
                  </span>
                </div>
              </div>
            ))}
          {vendors.filter(v => (v.risk_score || 0) >= 70).length === 0 && (
            <p className="text-xs text-mist text-center py-2">No high-risk vendors</p>
          )}
        </div>
      </div>
    </div>
  );
}
