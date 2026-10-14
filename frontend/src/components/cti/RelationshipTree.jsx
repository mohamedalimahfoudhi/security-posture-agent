import React from 'react';
import { ChevronDown, ChevronRight, Building2, Database, Server } from 'lucide-react';

export default function RelationshipTree({ data }) {
  const [expanded, setExpanded] = React.useState({});

  const toggleNode = (path) => {
    setExpanded(prev => ({
      ...prev,
      [path]: !prev[path]
    }));
  };

  const renderNode = (node, path = '', level = 0) => {
    const isExpanded = expanded[path];
    const hasChildren = node.children && node.children.length > 0;
    const paddingLeft = level * 16;

    return (
      <div key={path || 'root'} className="select-none">
        <div
          className="flex items-center gap-2 py-1 hover:bg-void/30 cursor-pointer"
          style={{ paddingLeft: `${paddingLeft}px` }}
          onClick={() => hasChildren && toggleNode(path)}
        >
          {hasChildren ? (
            isExpanded ? (
              <ChevronDown className="w-3 h-3 text-mist" />
            ) : (
              <ChevronRight className="w-3 h-3 text-mist" />
            )
          ) : (
            <span className="w-3 h-3" />
          )}
          {node.type === 'customer' && (
            <span className="w-4 h-4 text-viz-teal font-bold text-xs">C</span>
          )}
          {node.type === 'vendor' && (
            <Building2 className="w-4 h-4 text-viz-blue" />
          )}
          {node.type === 'technology' && (
            <Database className="w-4 h-4 text-viz-teal" />
          )}
          {node.type === 'service' && (
            <Server className="w-4 h-4 text-ember-bright" />
          )}
          <span className={`text-xs ${node.type === 'customer' ? 'font-semibold text-ink' : 'text-ink'}`}>
            {node.name}
          </span>
          {node.count && (
            <span className="text-[10px] text-mist ml-auto">{node.count}</span>
          )}
        </div>
        {hasChildren && isExpanded && (
          <div>
            {node.children.map((child, idx) => 
              renderNode(child, `${path}-${idx}`, level + 1)
            )}
          </div>
        )}
      </div>
    );
  };

  if (!data) {
    return (
      <div className="border border-hairline rounded-lg bg-[#0D0F11] p-4">
        <p className="text-xs text-mist">No architecture data available</p>
      </div>
    );
  }

  return (
    <div className="border border-hairline rounded-lg bg-[#0D0F11] p-4 max-h-96 overflow-auto">
      {renderNode(data)}
    </div>
  );
}
