import React, { useState } from 'react';
import { AlertTriangle, Trash2, X, RefreshCw } from 'lucide-react';
import { clearSocData } from '../services/api';
import { triggerSocRefresh } from '../context/SocRefreshContext';

export default function ClearDataModal({ isOpen, onClose }) {
  const [clearing, setClearing] = useState(false);
  const [error, setError] = useState(null);

  if (!isOpen) return null;

  const handleClear = async () => {
    setClearing(true);
    setError(null);
    try {
      await clearSocData();
      triggerSocRefresh();
      onClose();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || 'Failed to clear SOC data');
    } finally {
      setClearing(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-black/75 backdrop-blur-sm transition-opacity" 
        onClick={!clearing ? onClose : undefined} 
      />

      {/* Modal Dialog */}
      <div className="relative w-full max-w-md bg-[#111827] border border-red-500/30 rounded-xl p-6 shadow-2xl shadow-red-950/20 z-10 space-y-4 soc-glass">
        
        {/* Header */}
        <div className="flex items-start justify-between border-b border-gray-800 pb-3">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white tracking-wide">
                Clear all SOC data?
              </h3>
              <span className="text-[10px] font-mono text-red-400 uppercase">
                Destructive Action
              </span>
            </div>
          </div>
          
          <button 
            onClick={onClose} 
            disabled={clearing}
            className="text-slate-400 hover:text-white p-1 rounded-lg transition disabled:opacity-50"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="space-y-2 text-xs font-mono text-slate-300">
          <p className="leading-relaxed">
            This will permanently remove all events, alerts and incidents.
          </p>
          <p className="text-red-400/90 font-medium">
            This action cannot be undone.
          </p>
          <div className="pt-2 text-[11px] text-slate-400">
            <span className="text-slate-500">Note:</span> MITRE ATT&CK techniques, user accounts, and system configuration will remain safely preserved.
          </div>
        </div>

        {/* Error Notification if any */}
        {error && (
          <div className="p-2.5 rounded-lg bg-red-500/15 border border-red-500/30 text-red-300 text-xs font-mono">
            {error}
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex items-center justify-end space-x-3 pt-3 border-t border-gray-800">
          <button
            type="button"
            onClick={onClose}
            disabled={clearing}
            className="px-4 py-2 rounded-lg bg-gray-800/80 hover:bg-gray-700 text-slate-300 text-xs font-mono transition disabled:opacity-50"
          >
            Cancel
          </button>
          
          <button
            type="button"
            onClick={handleClear}
            disabled={clearing}
            className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-mono font-medium shadow-md shadow-red-950 transition disabled:opacity-60"
          >
            {clearing ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Clearing Database...</span>
              </>
            ) : (
              <>
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear All Data</span>
              </>
            )}
          </button>
        </div>

      </div>
    </div>
  );
}
