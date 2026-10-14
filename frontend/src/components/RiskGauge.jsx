import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';

export default function RiskGauge({ value = 0, max = 100 }) {
  const normalizedValue = Math.min(Math.max(value, 0), max);
  const percentage = (normalizedValue / max) * 100;
  
  // Determine color based on risk score
  let colorClass = 'text-sev-low';
  let fillColor = '#6b7280'; // Default gray
  
  if (normalizedValue >= 75) {
    colorClass = 'text-sev-critical';
    fillColor = '#ef4444'; // Red for critical
  } else if (normalizedValue >= 50) {
    colorClass = 'text-sev-high';
    fillColor = '#f97316'; // Orange for high
  } else if (normalizedValue >= 25) {
    colorClass = 'text-sev-elevated';
    fillColor = '#eab308'; // Yellow for elevated
  } else {
    colorClass = 'text-sev-low';
    fillColor = '#22c55e'; // Green for low
  }
  
  const data = [
    { name: 'Risk', value: percentage },
    { name: 'Remaining', value: 100 - percentage }
  ];
  
  return (
    <div className="flex items-center justify-center">
      <ResponsiveContainer width={80} height={80}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={25}
            outerRadius={35}
            startAngle={90}
            endAngle={-270}
            dataKey="value"
          >
            <Cell fill={fillColor} />
            <Cell fill="#1f2937" />
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute flex flex-col items-center justify-center">
        <span className={`text-lg font-bold font-mono ${colorClass}`}>
          {normalizedValue.toFixed(1)}
        </span>
      </div>
    </div>
  );
}
