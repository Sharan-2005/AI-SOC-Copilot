import React from 'react';
import { ShieldCheck } from 'lucide-react';

export default function EmptyState({ 
  icon: Icon = ShieldCheck, 
  title = 'No records found', 
  description = 'No telemetry matches the current query or filter criteria.',
  action
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
      <div className="p-3 rounded-xl bg-gray-800/60 border border-gray-700/60 text-slate-400 mb-3">
        <Icon className="w-8 h-8 text-cyan-400/80" />
      </div>
      <h3 className="text-sm font-semibold text-white">{title}</h3>
      <p className="text-xs text-slate-400 max-w-sm mt-1">{description}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
