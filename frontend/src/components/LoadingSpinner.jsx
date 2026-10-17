import React from 'react';
import { Loader2 } from 'lucide-react';

export default function LoadingSpinner({ message = 'Loading telemetry...' }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 space-y-3">
      <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
      <span className="text-xs font-mono text-slate-400">{message}</span>
    </div>
  );
}
