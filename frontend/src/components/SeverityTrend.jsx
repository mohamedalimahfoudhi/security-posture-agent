import { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { getSeverityTrend } from '../api/client';

const severityColors = {
  critical: '#E2483C',
  high: '#D65A3C',
  elevated: '#D9B23D',
  low: '#4C8C63',
};

export default function SeverityTrend() {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const trendData = await getSeverityTrend();
        setData(trendData);
        setError(null);
      } catch (err) {
        console.error('Failed to load severity trend:', err);
        setError('Failed to load data');
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, []);

  return (
    <div className="bg-panel border border-hairline rounded-lg p-4">
      <h3 className="text-base font-semibold font-display text-ink mb-4">SEVERITY TREND</h3>
      
      {loading ? (
        <div className="h-48 flex items-center justify-center">
          <span className="text-sm text-mist font-body">Loading...</span>
        </div>
      ) : error ? (
        <div className="h-48 flex items-center justify-center">
          <span className="text-sm text-ember-bright font-body">{error}</span>
        </div>
      ) : data.length === 0 ? (
        <div className="h-48 flex flex-col items-center justify-center gap-3">
          <svg className="w-8 h-8 text-mist" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 18L9 11.25l4.306 4.306a11.95 11.95 0 015.814-5.518l2.74-1.22m0 0l-3.714-.935m3.714.935l-.935 3.714" />
          </svg>
          <div className="text-center">
            <p className="text-sm font-semibold text-ink font-body">No trend data yet</p>
            <p className="text-xs text-mist font-body mt-1">Severity data will appear once findings are processed</p>
          </div>
        </div>

      ) : (
        <div className="h-48">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2B3032" />
              <XAxis 
                dataKey="time" 
                stroke="#8B93A1"
                style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: '11px' }}
              />
              <YAxis 
                stroke="#8B93A1"
                style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: '11px' }}
              />
              <Tooltip 
                contentStyle={{
                  backgroundColor: '#1E2224',
                  border: '1px solid #2B3032',
                  fontFamily: 'IBM Plex Mono, monospace',
                  fontSize: '12px',
                }}
              />
              <Line 
                type="monotone" 
                dataKey="critical" 
                stroke={severityColors.critical} 
                strokeWidth={2}
                dot={false}
              />
              <Line 
                type="monotone" 
                dataKey="high" 
                stroke={severityColors.high} 
                strokeWidth={2}
                dot={false}
              />
              <Line 
                type="monotone" 
                dataKey="elevated" 
                stroke={severityColors.elevated} 
                strokeWidth={2}
                dot={false}
              />
              <Line 
                type="monotone" 
                dataKey="low" 
                stroke={severityColors.low} 
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      <div className="flex gap-4 mt-4 pt-4 border-t border-hairline">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-sev-critical" />
          <span className="text-xs text-mist font-body">Critical</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-sev-high" />
          <span className="text-xs text-mist font-body">High</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-sev-elevated" />
          <span className="text-xs text-mist font-body">Elevated</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-sev-low" />
          <span className="text-xs text-mist font-body">Low</span>
        </div>
      </div>
    </div>
  );
}
