import React, { useState } from 'react';
import { Play, ShieldAlert, KeyRound, Globe, RefreshCw, CheckCircle2, AlertTriangle, Radio, Network } from 'lucide-react';
import { simulateAttack } from '../services/api';

export default function SimulatorControls({ onSimulationComplete }) {
  const [runningScenario, setRunningScenario] = useState(null);
  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);

  const handleRunSimulation = async (scenario, label) => {
    setRunningScenario(scenario);
    setMessage(null);
    setError(null);
    try {
      const res = await simulateAttack(scenario);
      const evCount = res.events_generated ?? res.packets_generated ?? 0;
      const alCount = res.alerts_created ?? (res.detection_state?.includes('POSSIBLE') ? 1 : 0);
      setMessage(
        `Simulation '${label}' succeeded: ${evCount} packets/events processed, ${alCount} alert(s) generated [State: ${res.detection_state || res.scenario}].`
      );
      if (onSimulationComplete) {
        onSimulationComplete();
      }
    } catch (err) {
      setError(err.response?.data?.detail || err.message || `Failed to run ${label} simulation`);
    } finally {
      setRunningScenario(null);
    }
  };

  return (
    <div className="p-4 sm:p-5 rounded-xl soc-glass border border-gray-800 space-y-3">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-gray-800 pb-3">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 rounded-lg bg-red-500/10 text-red-400 border border-red-500/30">
            <Play className="w-4 h-4 fill-red-400/30" />
          </div>
          <div>
            <h3 className="text-xs font-bold font-mono text-white uppercase tracking-wider">
              Attack Scenario Simulator
            </h3>
            <p className="text-[11px] text-slate-400">
              Generate realistic attack & flood telemetry to trigger deterministic detection engines.
            </p>
          </div>
        </div>
        <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800 self-start sm:self-auto">
          PHASE 4 &amp; 5 SIMULATOR
        </span>
      </div>

      {/* Buttons Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        <button
          onClick={() => handleRunSimulation('brute_force', 'Brute Force')}
          disabled={runningScenario !== null}
          className="flex items-center justify-center space-x-2 px-3.5 py-2 rounded-lg bg-black/40 hover:bg-red-500/10 border border-gray-800 hover:border-red-500/40 text-slate-200 hover:text-red-400 text-xs font-mono font-medium transition disabled:opacity-50"
        >
          {runningScenario === 'brute_force' ? (
            <RefreshCw className="w-3.5 h-3.5 animate-spin text-red-400" />
          ) : (
            <KeyRound className="w-3.5 h-3.5 text-red-400" />
          )}
          <span>Simulate Brute Force</span>
        </button>

        <button
          onClick={() => handleRunSimulation('port_scan', 'Port Scan')}
          disabled={runningScenario !== null}
          className="flex items-center justify-center space-x-2 px-3.5 py-2 rounded-lg bg-black/40 hover:bg-amber-500/10 border border-gray-800 hover:border-amber-500/40 text-slate-200 hover:text-amber-400 text-xs font-mono font-medium transition disabled:opacity-50"
        >
          {runningScenario === 'port_scan' ? (
            <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-400" />
          ) : (
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
          )}
          <span>Simulate Port Scan</span>
        </button>

        <button
          onClick={() => handleRunSimulation('web_attack', 'Web Attack')}
          disabled={runningScenario !== null}
          className="flex items-center justify-center space-x-2 px-3.5 py-2 rounded-lg bg-black/40 hover:bg-purple-500/10 border border-gray-800 hover:border-purple-500/40 text-slate-200 hover:text-purple-400 text-xs font-mono font-medium transition disabled:opacity-50"
        >
          {runningScenario === 'web_attack' ? (
            <RefreshCw className="w-3.5 h-3.5 animate-spin text-purple-400" />
          ) : (
            <Globe className="w-3.5 h-3.5 text-purple-400" />
          )}
          <span>Simulate Web Attack</span>
        </button>

        <button
          onClick={() => handleRunSimulation('icmp_flood', 'Possible ICMP DoS')}
          disabled={runningScenario !== null}
          className="flex items-center justify-center space-x-2 px-3.5 py-2 rounded-lg bg-black/40 hover:bg-rose-500/10 border border-gray-800 hover:border-rose-500/40 text-slate-200 hover:text-rose-400 text-xs font-mono font-medium transition disabled:opacity-50"
        >
          {runningScenario === 'icmp_flood' ? (
            <RefreshCw className="w-3.5 h-3.5 animate-spin text-rose-400" />
          ) : (
            <Radio className="w-3.5 h-3.5 text-rose-400" />
          )}
          <span>Simulate ICMP DoS</span>
        </button>

        <button
          onClick={() => handleRunSimulation('icmp_ddos', 'Possible ICMP DDoS')}
          disabled={runningScenario !== null}
          className="flex items-center justify-center space-x-2 px-3.5 py-2 rounded-lg bg-black/40 hover:bg-fuchsia-500/10 border border-gray-800 hover:border-fuchsia-500/40 text-slate-200 hover:text-fuchsia-400 text-xs font-mono font-medium transition disabled:opacity-50"
        >
          {runningScenario === 'icmp_ddos' ? (
            <RefreshCw className="w-3.5 h-3.5 animate-spin text-fuchsia-400" />
          ) : (
            <Network className="w-3.5 h-3.5 text-fuchsia-400" />
          )}
          <span>Simulate ICMP DDoS</span>
        </button>
      </div>

      {/* Success Notification */}
      {message && (
        <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/80 text-[11px] font-mono text-emerald-300 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{message}</span>
          </div>
          <span className="text-[10px] text-emerald-400 underline cursor-pointer" onClick={() => setMessage(null)}>
            Dismiss
          </span>
        </div>
      )}

      {/* Error Notification */}
      {error && (
        <div className="p-3 rounded-lg bg-red-950/40 border border-red-800 text-[11px] font-mono text-red-300 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
          <span className="text-[10px] text-red-400 underline cursor-pointer" onClick={() => setError(null)}>
            Dismiss
          </span>
        </div>
      )}
    </div>
  );
}
