export default function StatCard({ 
  label, 
  value, 
  icon: Icon, 
  trend, 
  colorClass = 'text-text-primary',
  bgColorClass = 'bg-panel',
  accentColor = null
}) {
  const accentStyle = accentColor ? { borderLeftColor: accentColor, borderLeftWidth: '3px' } : {};
  
  return (
    <div 
      className={`${bgColorClass} border border-border-base rounded-md p-4 relative hover:border-border-subtle transition-all duration-150 shadow-sm`}
      style={accentStyle}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <div className="text-[11px] font-semibold text-text-muted uppercase tracking-wider font-body mb-1 truncate">
            {label}
          </div>
          <div className={`text-2xl font-bold font-mono tracking-tight ${colorClass}`}>
            {value}
          </div>
          {trend && (
            <div className="text-xs text-text-secondary mt-1 font-body">
              {trend}
            </div>
          )}
        </div>
        {Icon && (
          <div className="text-text-muted/60 shrink-0 ml-2">
            <Icon size={18} />
          </div>
        )}
      </div>
    </div>
  );
}
