import { useState, useEffect } from 'react';
import { getIntelligenceDashboard } from '../api/client';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line } from 'recharts';

// Severity colors matching the app's design tokens
const SEVERITY_COLORS = {
  CRITICAL: '#E2483C',
  HIGH: '#D65A3C',
  MEDIUM: '#D9B23D',
  LOW: '#4C8C63',
};

// Tier-2 data-viz palette for ransomware groups
const RANSOMWARE_COLORS = [
  '#3B82F6', '#8B5CF6', '#EC4899', '#F59E0B', '#10B981',
  '#06B6D4', '#6366F1', '#EF4444', '#84CC16', '#F97316'
];

export default function ReportsPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    try {
      setLoading(true);
      setError(null);
      const dashboardData = await getIntelligenceDashboard();
      setData(dashboardData);
    } catch (err) {
      console.error('Failed to load intelligence dashboard:', err);
      setError('Failed to load intelligence dashboard');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="h-full bg-panel border border-hairline rounded-lg overflow-hidden flex flex-col">
        <div className="p-6 border-b border-hairline">
          <h2 className="text-lg font-semibold text-ink font-display">Intelligence Dashboard</h2>
          <p className="text-xs text-mist font-body mt-1">Real-time threat intelligence and posture analysis</p>
        </div>
        <div className="flex-1 overflow-y-auto p-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="bg-void border border-hairline rounded-lg p-4 animate-pulse h-64"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-sm text-error font-body">{error}</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-sm text-mist font-body">No intelligence data available</p>
      </div>
    );
  }

  // Process alerts by day for stacked bar chart
  const alertsByDayData = processDataForStackedBar(data.alerts_by_day);

  return (
    <div className="h-full bg-panel border border-hairline rounded-lg overflow-hidden flex flex-col">
      <div className="p-6 border-b border-hairline">
        <h2 className="text-lg font-semibold text-ink font-display">Intelligence Dashboard</h2>
        <p className="text-xs text-mist font-body mt-1">Real-time threat intelligence and posture analysis</p>
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Panel 1: Stacked Bar Chart - Alerts by Day x Severity */}
          <DashboardPanel title="Alerts by Severity — Last 7 Days" fullHeight={false}>
            {alertsByDayData.length > 0 ? (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={alertsByDayData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                    <XAxis 
                      dataKey="day" 
                      tick={{ fill: '#9ca3af', fontSize: 11 }}
                      tickFormatter={(value) => new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                    />
                    <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333', borderRadius: '8px' }}
                      labelStyle={{ color: '#9ca3af' }}
                    />
                    <Legend wrapperStyle={{ color: '#9ca3af', fontSize: 11 }} />
                    <Bar dataKey="CRITICAL" stackId="a" fill={SEVERITY_COLORS.CRITICAL} />
                    <Bar dataKey="HIGH" stackId="a" fill={SEVERITY_COLORS.HIGH} />
                    <Bar dataKey="MEDIUM" stackId="a" fill={SEVERITY_COLORS.MEDIUM} />
                    <Bar dataKey="LOW" stackId="a" fill={SEVERITY_COLORS.LOW} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-64 flex items-center justify-center">
                <p className="text-sm text-mist font-body">No alert data available</p>
              </div>
            )}
          </DashboardPanel>

          {/* Panel 2: Donut Chart - Ransomware Groups */}
          <DashboardPanel title="Top Ransomware Groups Observed" fullHeight={false}>
            {data.ransomware_groups.length > 0 ? (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={data.ransomware_groups}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={2}
                      dataKey="count"
                      nameKey="group"
                      label={(entry) => entry.group}
                      labelLine={false}
                    >
                      {data.ransomware_groups.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={RANSOMWARE_COLORS[index % RANSOMWARE_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333', borderRadius: '8px' }}
                      labelStyle={{ color: '#9ca3af' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-64 flex items-center justify-center">
                <p className="text-sm text-mist font-body">No ransomware group data available</p>
              </div>
            )}
          </DashboardPanel>

          {/* Panel 3: Table - Recent Intelligence */}
          <DashboardPanel title="Recent Intelligence" fullHeight={false}>
            {data.recent_assessments.length > 0 ? (
              <div className="overflow-x-auto max-h-64">
                <table className="w-full text-sm border-separate border-spacing-y-2">
                  <thead>
                    <tr className="text-xs uppercase tracking-wide text-mist">
                      <th className="pb-2 text-left font-semibold">Event ID</th>
                      <th className="pb-2 text-left font-semibold">Date</th>
                      <th className="pb-2 text-left font-semibold">MITRE Techniques</th>
                      <th className="pb-2 text-left font-semibold">Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.recent_assessments.map((assessment) => (
                      <tr key={assessment.id} className="bg-void border border-hairline rounded-lg">
                        <td className="py-2 px-3 rounded-l-lg text-ink font-medium font-body truncate max-w-[150px]">
                          {assessment.event_id ? assessment.event_id : '—'}
                        </td>
                        <td className="py-2 px-3 text-mist font-mono text-xs">
                          {assessment.created_at ? new Date(assessment.created_at).toLocaleDateString() : '—'}
                        </td>
                        <td className="py-2 px-3">
                          {assessment.techniques ? (
                            <div className="flex flex-wrap gap-1">
                              {assessment.techniques.split(', ').map((tech, idx) => (
                                <span key={idx} className="text-xs bg-ember-dim text-ink px-2 py-0.5 rounded font-mono">
                                  {tech}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-xs text-mist">—</span>
                          )}
                        </td>
                        <td className="py-2 px-3 rounded-r-lg">
                          <span className={`text-xs font-semibold px-2 py-0.5 rounded ${
                            assessment.severity === 'CRITICAL' ? 'bg-sev-critical text-white' :
                            assessment.severity === 'HIGH' ? 'bg-sev-high text-white' :
                            assessment.severity === 'MEDIUM' ? 'bg-sev-medium text-white' :
                            assessment.severity === 'LOW' ? 'bg-sev-low text-white' :
                            'bg-mist text-ink'
                          }`}>
                            {assessment.severity || 'UNKNOWN'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="h-64 flex items-center justify-center">
                <p className="text-sm text-mist font-body">No recent intelligence available</p>
              </div>
            )}
          </DashboardPanel>

          {/* Panel 4: Bar Chart - Countries */}
          <DashboardPanel title="Third-Party Incidents by Country" fullHeight={false}>
            {data.countries.length > 0 ? (
              <div className="h-64 overflow-y-auto">
                <div className="space-y-2">
                  {data.countries.map((country, index) => (
                    <div key={index} className="flex items-center justify-between">
                      <span className="text-sm text-ink font-body">{country.country}</span>
                      <div className="flex items-center gap-3">
                        <div className="w-24 bg-void rounded-full h-2">
                          <div
                            className="h-2 rounded-full bg-ember-dim"
                            style={{ width: `${(country.count / data.countries[0].count) * 100}%` }}
                          />
                        </div>
                        <span className="text-sm text-mist font-mono w-8 text-right">{country.count}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="h-64 flex items-center justify-center">
                <p className="text-sm text-mist font-body">No country data available</p>
              </div>
            )}
          </DashboardPanel>

          {/* Panel 5: Assessment Confidence Trend */}
          <DashboardPanel title="Assessment Confidence Trend" fullHeight={false} fullRow={true}>
            {data.confidence_trend.length > 0 ? (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={data.confidence_trend.reverse()}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                    <XAxis 
                      dataKey="day" 
                      tick={{ fill: '#9ca3af', fontSize: 11 }}
                      tickFormatter={(value) => new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                    />
                    <YAxis 
                      domain={[0, 100]}
                      tick={{ fill: '#9ca3af', fontSize: 11 }}
                      label={{ value: 'Confidence %', angle: -90, position: 'insideLeft', fill: '#9ca3af', fontSize: 10 }}
                    />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333', borderRadius: '8px' }}
                      labelStyle={{ color: '#9ca3af' }}
                      formatter={(value) => [`${value.toFixed(1)}%`, 'Avg Confidence']}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="avg_confidence" 
                      stroke="#3B82F6" 
                      strokeWidth={2}
                      dot={{ fill: '#3B82F6', r: 3 }}
                      activeDot={{ r: 5 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-64 flex items-center justify-center">
                <p className="text-sm text-mist font-body">No confidence trend data available</p>
              </div>
            )}
          </DashboardPanel>
        </div>
      </div>
    </div>
  );
}

// Helper component for dashboard panels
function DashboardPanel({ title, children, fullHeight = false, fullRow = false }) {
  return (
    <div className={`bg-panel border border-hairline rounded-lg overflow-hidden ${fullRow ? 'lg:col-span-2' : ''}`}>
      <div className="p-4 border-b border-hairline">
        <h3 className="text-sm font-semibold text-ink font-display">{title}</h3>
      </div>
      <div className="p-4">
        {children}
      </div>
    </div>
  );
}

// Helper function to process alerts by day for stacked bar chart
function processDataForStackedBar(alertsByDay) {
  const dayMap = {};
  
  alertsByDay.forEach(({ day, severity, count }) => {
    if (!dayMap[day]) {
      dayMap[day] = { day, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    }
    if (dayMap[day][severity] !== undefined) {
      dayMap[day][severity] += count;
    }
  });

  return Object.values(dayMap).sort((a, b) => new Date(a.day) - new Date(b.day));
}
