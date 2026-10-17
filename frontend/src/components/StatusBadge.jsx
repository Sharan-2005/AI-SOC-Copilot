import React from 'react';

const STATUS_CONFIG = {
  OPEN: {
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/30',
    text: 'text-blue-400'
  },
  INVESTIGATING: {
    bg: 'bg-purple-500/10',
    border: 'border-purple-500/30',
    text: 'text-purple-400'
  },
  CONTAINED: {
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
    text: 'text-emerald-400'
  },
  RESOLVED: {
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
    text: 'text-emerald-400'
  },
  FALSE_POSITIVE: {
    bg: 'bg-gray-500/10',
    border: 'border-gray-500/30',
    text: 'text-gray-400'
  }
};

export default function StatusBadge({ status }) {
  const norm = (status || 'OPEN').toUpperCase();
  const conf = STATUS_CONFIG[norm] || STATUS_CONFIG.OPEN;

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-mono font-medium border ${conf.bg} ${conf.border} ${conf.text}`}>
      {norm}
    </span>
  );
}
