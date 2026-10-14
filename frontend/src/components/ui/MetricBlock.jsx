import React from 'react';

export default function MetricBlock({ value, label, highlight = false }) {
  return (
    <div className={`flex flex-col ${highlight ? 'text-ink' : 'text-mist'}`}>
      <span className="text-2xl font-display font-semibold leading-none mb-1">
        {value}
      </span>
      <span className="text-[10px] uppercase tracking-wider font-bold opacity-80">
        {label}
      </span>
    </div>
  );
}
