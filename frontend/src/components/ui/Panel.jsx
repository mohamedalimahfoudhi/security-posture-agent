import React from 'react';

export default function Panel({ children, className = '', title, headerRight }) {
  return (
    <div className={`bg-panel border border-border-base rounded-md overflow-hidden flex flex-col shadow-sm ${className}`}>
      {(title || headerRight) && (
        <div className="px-4 py-3 border-b border-border-base flex items-center justify-between bg-panel">
          {title && <h3 className="font-sans font-semibold text-text-primary text-sm tracking-tight">{title}</h3>}
          {headerRight && <div>{headerRight}</div>}
        </div>
      )}
      <div className="p-4 flex-1 overflow-auto custom-scrollbar">
        {children}
      </div>
    </div>
  );
}
