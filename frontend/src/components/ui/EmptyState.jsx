import React from 'react';
import { AlertCircle } from 'lucide-react';

export default function EmptyState({ message, subtext, icon: Icon = AlertCircle }) {
  return (
    <div className="flex flex-col items-center justify-center p-8 text-center bg-panel/30 border border-dashed border-hairline rounded-lg">
      <Icon className="w-8 h-8 text-mist mb-3 opacity-50" />
      <p className="text-sm text-ink font-medium">{message}</p>
      {subtext && <p className="text-xs text-mist mt-1">{subtext}</p>}
    </div>
  );
}
