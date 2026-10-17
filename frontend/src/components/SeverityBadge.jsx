import React from 'react';

const SEVERITY_CONFIG = {
  CRITICAL: {
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    text: 'text-red-400',
    dot: 'bg-red-500'
  },
  HIGH: {
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/30',
    text: 'text-orange-400',
    dot: 'bg-orange-500'
  },
  MEDIUM: {
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    text: 'text-amber-400',
    dot: 'bg-amber-500'
  },
  LOW: {
    bg: 'bg-cyan-500/10',
    border: 'border-cyan-500/30',
    text: 'text-cyan-400',
    dot: 'bg-cyan-500'
  }
};

export default function SeverityBadge({ severity }) {
  const norm = (severity || 'LOW').toUpperCase();
  const conf = SEVERITY_CONFIG[norm] || SEVERITY_CONFIG.LOW;

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium border ${conf.bg} ${conf.border} ${conf.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${conf.dot} ${norm === 'CRITICAL' ? 'animate-ping' : ''}`} />
      {norm}
    </span>
  );
}
