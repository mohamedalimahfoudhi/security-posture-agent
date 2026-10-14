import { useState, useEffect, useRef } from 'react';
import { Bell } from 'lucide-react';
import { getAlerts } from '../api/client';

export default function NotificationBell({ onViewAll }) {
  const [alerts, setAlerts] = useState([]);
  const [open, setOpen] = useState(false);
  const ref = useRef();

  useEffect(() => {
    loadAlerts();
    const onClick = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    window.addEventListener('click', onClick);
    return () => window.removeEventListener('click', onClick);
  }, []);

  async function loadAlerts() {
    try {
      const data = await getAlerts();
      // sort newest first
      data.sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
      setAlerts(data);
    } catch (e) {
      console.error('Failed to load alerts for notification bell', e);
    }
  }

  const highNewCount = alerts.filter(a => a.status === 'NEW' && (a.risk_level === 'CRITICAL' || a.risk_level === 'HIGH')).length;

  return (
    <div className="relative" ref={ref}>
      <button onClick={() => setOpen(!open)} className="relative p-2 rounded hover:bg-panel">
        <Bell className="w-5 h-5 text-mist" />
        {highNewCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 inline-flex items-center justify-center rounded-full bg-ember-bright text-white text-[10px] px-1 py-0.5">
            {highNewCount}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-96 bg-panel border border-hairline rounded-lg shadow-lg z-50 p-3">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-sm font-semibold text-ink">Alerts</h4>
            <button className="text-xs text-mist" onClick={() => { loadAlerts(); }}>Refresh</button>
          </div>
          <div className="max-h-72 overflow-y-auto space-y-2">
            {alerts.slice(0,8).map((a) => (
              <div key={a.id} className="p-2 bg-void border border-hairline rounded hover:bg-panel/60 transition-colors">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded ${a.risk_level === 'CRITICAL' ? 'bg-sev-critical text-void' : a.risk_level === 'HIGH' ? 'bg-sev-high text-void' : 'bg-mist text-ink'}`}>
                        {a.risk_level}
                      </span>
                      <div className="text-sm text-ink font-medium">{a.title || a.event}</div>
                    </div>
                    <div className="text-xs text-mist mt-1">Confidence: {a.confidence_score ?? 'N/A'}%</div>
                    {a.escalation_recommendation && (
                      <div className="mt-1 inline-block text-xs font-semibold px-2 py-0.5 rounded bg-amber-100 text-amber-800">{a.escalation_recommendation}</div>
                    )}
                  </div>
                  <div className="text-xs text-mist whitespace-nowrap">{a.created_at ? new Date(a.created_at).toLocaleString() : ''}</div>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-3 text-right">
            <button onClick={() => { setOpen(false); onViewAll?.(); }} className="text-sm text-ember-bright font-semibold">View all alerts</button>
          </div>
        </div>
      )}
    </div>
  );
}
