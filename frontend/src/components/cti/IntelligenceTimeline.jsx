import React from 'react';

export default function IntelligenceTimeline({ events, dateField = 'created_at', groupBy = 'week' }) {
  if (!events || events.length === 0) {
    return (
      <div className="border border-hairline rounded-lg bg-[#0D0F11] p-4">
        <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-4">ACTIVITY TIMELINE</h3>
        <p className="text-xs text-mist">No activity data available</p>
      </div>
    );
  }

  const now = new Date();
  const ninetyDaysAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
  
  const recentEvents = events.filter(e => {
    const eventDate = e[dateField] ? new Date(e[dateField]) : new Date(e.created_at);
    return eventDate >= ninetyDaysAgo;
  });

  if (recentEvents.length === 0) {
    return (
      <div className="border border-hairline rounded-lg bg-[#0D0F11] p-4">
        <h3 className="text-xs font-semibold text-ink uppercase tracking-wider mb-4">ACTIVITY TIMELINE</h3>
        <p className="text-xs text-mist">No activity in the last 90 days</p>
      </div>
    );
  }

  // Group by week
  const weeks = {};
  recentEvents.forEach(e => {
    const date = e[dateField] ? new Date(e[dateField]) : new Date(e.created_at);
    const weekStart = new Date(date);
    weekStart.setDate(date.getDate() - date.getDay());
    weekStart.setHours(0, 0, 0, 0);
    const weekKey = weekStart.toISOString().split('T')[0];
    if (!weeks[weekKey]) weeks[weekKey] = 0;
    weeks[weekKey]++;
  });

  const sortedWeeks = Object.entries(weeks).sort((a, b) => a[0].localeCompare(b[0]));
  const maxCount = Math.max(...Object.values(weeks), 1);

  return (
    <div className="border border-hairline rounded-lg bg-[#0D0F11] p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xs font-semibold text-ink uppercase tracking-wider">ACTIVITY TIMELINE</h3>
        <span className="text-[10px] text-mist">LAST 90 DAYS</span>
      </div>
      
      <div className="space-y-2">
        {sortedWeeks.map(([week, count]) => (
          <div key={week} className="flex items-center gap-3">
            <span className="text-[10px] text-mist font-mono w-20">
              {new Date(week).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
            </span>
            <div className="flex-1 h-2 bg-void rounded overflow-hidden">
              <div 
                className="h-full bg-ember-bright transition-all"
                style={{ width: `${(count / maxCount) * 100}%` }}
              />
            </div>
            <span className="text-xs font-mono text-ink w-6 text-right">{count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
