import StatCard from './StatCard';
import RiskGauge from './RiskGauge';
import { FileText, AlertTriangle, Shield, Cpu, Gauge } from 'lucide-react';

export default function StatusStrip({ summary = {}, techCount = 0 }) {

  console.log("STATUS STRIP RECEIVED:", summary, "TECH COUNT:", techCount);

  const {
    critical_threats = 0,
    high_threats = 0,
    total_assessments = 0,
    average_risk_score = 0
  } = summary;

  return (
    <div className="bg-panel border-b border-hairline px-6 py-4">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        
        <StatCard
          label="Assessments"
          value={total_assessments}
          icon={FileText}
          colorClass="text-ink"
          accentColor="#3B82F6"
        />
        
        <StatCard
          label="Critical"
          value={critical_threats}
          icon={AlertTriangle}
          colorClass="text-ember-bright"
          accentColor="#E2483C"
        />
        
        <StatCard
          label="High"
          value={high_threats}
          icon={Shield}
          colorClass="text-ink"
          accentColor="#D65A3C"
        />
        
        <StatCard
          label="Technologies"
          value={techCount}
          icon={Cpu}
          colorClass="text-ink"
          accentColor="#14B8A6"
        />
        
        <div className="bg-panel border border-hairline rounded-lg p-4 flex items-center justify-between hover:shadow-md hover:border-hairline/80 transition-all duration-200">
          <div className="flex-1">
            <div className="text-xs font-medium text-mist uppercase tracking-wide font-body mb-1">
              Avg Risk
            </div>
            <div className="text-2xl font-bold font-mono text-ink">
              {average_risk_score.toFixed(1)}
            </div>
          </div>
          <div className="relative">
            <RiskGauge value={average_risk_score} max={100} />
          </div>
        </div>
        
      </div>
    </div>
  );
}