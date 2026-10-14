import React from 'react';

export default function FilterBar({ filters, onFilterChange, search, onSearchChange, placeholder = "Search..." }) {
  return (
    <div className="flex flex-wrap items-center gap-3 mb-6 bg-panel p-2.5 rounded-md border border-border-base">
      {/* Search Input */}
      <div className="flex-1 min-w-[200px]">
        <input 
          type="text" 
          value={search} 
          onChange={(e) => onSearchChange(e.target.value)} 
          placeholder={placeholder}
          className="w-full bg-bg-surface border border-border-base rounded px-3 py-1.5 text-xs text-text-primary placeholder-text-muted focus:border-accent-primary focus:outline-none transition-colors"
        />
      </div>
      
      {/* Dropdown Filters */}
      {filters && Object.keys(filters).map(key => (
        <select 
          key={key}
          value={filters[key].value}
          onChange={(e) => onFilterChange(key, e.target.value)}
          className="bg-bg-surface border border-border-base rounded px-3 py-1.5 text-xs text-text-primary focus:border-accent-primary focus:outline-none transition-colors"
        >
          {filters[key].options.map(opt => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      ))}
    </div>
  );
}
