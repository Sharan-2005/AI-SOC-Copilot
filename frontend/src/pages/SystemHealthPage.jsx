import React, { useState, useEffect } from 'react';
import { 
  Server, 
  Database, 
  Cpu, 
  CheckCircle2, 
  AlertTriangle, 
  RefreshCw, 
  Terminal,
  Clock,
  ShieldCheck
} from 'lucide-react';
import { checkHealth } from '../services/api';
import LoadingSpinner from '../components/LoadingSpinner';
import { useSocRefresh } from '../context/SocRefreshContext';

export default function SystemHealthPage() {
  const [healthData, setHealthData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastChecked, setLastChecked] = useState(null);

  const fetchHealth = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await checkHealth();
      setHealthData(data);
      setLastChecked(new Date().toLocaleTimeString());
    } catch (err) {
      setError(err.message || 'Failed to connect to backend server');
      setLastChecked(new Date().toLocaleTimeString());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  useSocRefresh(fetchHealth);

  const isDbConnected = healthData?.database?.connected === true;

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      
      {/* Top Banner */}
      <div className="p-6 rounded-xl soc-glass border border-gray-800 relative overflow-hidden">
        <div className="absolute -right-12 -top-12 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <span className="text-xs font-mono uppercase tracking-wider text-cyan-400 font-semibold">
              Telemetry & Infrastructure Diagnostics
            </span>
            <h2 className="text-2xl font-bold text-white mt-1">System Health & Backend Telemetry</h2>
            <p className="text-sm text-slate-400 max-w-2xl mt-1">
              Live heartbeat telemetry validating FastAPI application runtime, Supabase PostgreSQL pooler, and endpoint connectivity.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <div className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-2 ${
              error 
                ? 'bg-red-500/10 border-red-500/30 text-red-400'
                : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
            }`}>
              <span className={`w-2 h-2 rounded-full ${error ? 'bg-red-500 animate-ping' : 'bg-emerald-400 animate-pulse'}`} />
              {error ? 'BACKEND UNREACHABLE' : 'CORE SERVICES OPERATIONAL'}
            </div>

            <button
              onClick={fetchHealth}
              disabled={loading}
              className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-md bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/40 text-cyan-300 text-xs font-medium transition disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>{loading ? 'Probing...' : 'Re-check'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Diagnostics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* Service Health Card */}
        <div className="p-5 rounded-xl soc-glass border border-gray-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
                <Server className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white">FastAPI Core</h3>
                <p className="text-xs text-slate-400">REST Gateway</p>
              </div>
            </div>
            {error ? (
              <AlertTriangle className="w-5 h-5 text-amber-400" />
            ) : (
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            )}
          </div>

          <div className="border-t border-gray-800/80 pt-3 space-y-2 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-slate-400">Status:</span>
              <span className={error ? 'text-red-400' : 'text-emerald-400 font-semibold'}>
                {error ? 'Unreachable' : healthData?.status?.toUpperCase() || 'OK'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Version:</span>
              <span className="text-slate-200">{healthData?.version || '1.0.0'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Environment:</span>
              <span className="text-cyan-400">{healthData?.environment || 'development'}</span>
            </div>
          </div>
        </div>

        {/* Database Health Card */}
        <div className="p-5 rounded-xl soc-glass border border-gray-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
                <Database className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white">Supabase PostgreSQL</h3>
                <p className="text-xs text-slate-400">Cloud Relational Store</p>
              </div>
            </div>
            {isDbConnected ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-5 h-5 text-amber-400" />
            )}
          </div>

          <div className="border-t border-gray-800/80 pt-3 space-y-2 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-slate-400">Dialect:</span>
              <span className="text-slate-200 font-semibold">PostgreSQL</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Connection:</span>
              <span className={isDbConnected ? 'text-emerald-400 font-semibold' : 'text-amber-400'}>
                {isDbConnected ? 'CONNECTED' : 'STANDBY / PENDING'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Latency:</span>
              <span className="text-slate-300">
                {healthData?.database?.latency_ms != null ? `${healthData.database.latency_ms} ms` : 'N/A'}
              </span>
            </div>
          </div>
        </div>

        {/* Telemetry Pipeline Card */}
        <div className="p-5 rounded-xl soc-glass border border-gray-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <Cpu className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white">SOC Architecture</h3>
                <p className="text-xs text-slate-400">Phase Status</p>
              </div>
            </div>
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
          </div>

          <div className="border-t border-gray-800/80 pt-3 space-y-2 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-slate-400">Active Phase:</span>
              <span className="text-cyan-300 font-semibold">Phase 3 (Frontend Console)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Next Phase:</span>
              <span className="text-slate-300">Phase 4 (Detection Engine)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">AI Guardrail:</span>
              <span className="text-emerald-400">Enforced</span>
            </div>
          </div>
        </div>

      </div>

      {/* Raw Health JSON Terminal */}
      <div className="p-5 rounded-xl soc-glass border border-gray-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span>LIVE HEALTH TELEMETRY [GET /api/health]</span>
          </div>
          <span className="text-[11px] font-mono text-slate-500">
            Last Checked: {lastChecked || '--:--:--'}
          </span>
        </div>

        <div className="soc-terminal-box bg-black/60 rounded-lg p-4 border border-gray-800/60 overflow-x-auto">
          {error ? (
            <div className="text-red-400 font-mono text-xs">
              [ERROR] Failed to reach backend at /api/health: {error}
            </div>
          ) : healthData ? (
            <pre className="text-xs font-mono text-cyan-300 leading-relaxed">
              {JSON.stringify(healthData, null, 2)}
            </pre>
          ) : (
            <div className="text-slate-500 font-mono text-xs">Loading health telemetry...</div>
          )}
        </div>
      </div>

    </div>
  );
}
