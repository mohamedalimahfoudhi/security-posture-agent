import React, { useEffect } from 'react';
import { X } from 'lucide-react';

export default function DetailDrawer({ isOpen, onClose, title, subtitle, children }) {
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }
    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-void/80 backdrop-blur-sm transition-opacity"
        onClick={onClose}
      />
      
      {/* Drawer */}
      <div className="relative w-full max-w-2xl bg-panel h-full border-l border-border-base shadow-2xl flex flex-col animate-slide-in-right">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-border-base bg-panel">
          <div>
            <h2 className="text-base font-semibold text-text-primary tracking-tight font-sans">{title}</h2>
            {subtitle && <p className="text-xs text-text-muted mt-0.5 font-body">{subtitle}</p>}
          </div>
          <button 
            onClick={onClose}
            className="p-1.5 text-text-muted hover:text-text-primary hover:bg-bg-surface rounded-md transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        
        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 custom-scrollbar space-y-6">
          {children}
        </div>
      </div>
    </div>
  );
}
