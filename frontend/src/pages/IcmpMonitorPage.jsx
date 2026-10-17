import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { 
  Radio, 
  Play, 
  Square, 
  RefreshCw, 
  AlertTriangle, 
  ShieldAlert, 
  Activity, 
  Network, 
  CheckCircle2, 
  Cpu, 
  Zap, 
  Sliders, 
  HelpCircle,
  ExternalLink,
  RotateCcw,
  Sparkles,
  Info,
  ChevronDown,
  ChevronUp,
  Download,
  Target,
  Server,
  ArrowDownLeft,
  ArrowUpRight,
  ShieldCheck,
  X
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  CartesianGrid,
  ReferenceLine
} from 'recharts';
import { 
  fetchIcmpStatus, 
  fetchIcmpStats, 
  fetchIcmpEvents, 
  fetchIcmpInterfaces, 
  fetchActiveInterface,
  fetchDriverStatus,
  fetchProtectedTargets,
  updateProtectedTargets,
  startIcmpMonitor, 
  stopIcmpMonitor, 
  simulateIcmpTraffic, 
  resetIcmpStats 
} from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';
import EmptyState from '../components/EmptyState';
import { useTheme } from '../context/ThemeContext';
import { useSocRefresh } from '../context/SocRefreshContext';

export default function IcmpMonitorPage() {
  const { chartColors } = useTheme();

  // Status & Telemetry
  const [status, setStatus] = useState(null);
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [activeIface, setActiveIface] = useState(null);
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('Wi-Fi');
  const [driverStatus, setDriverStatus] = useState({ available: false, message: '' });

  // UI Controls
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [error, setError] = useState(null);
  const [driverError, setDriverError] = useState(null);
  const [successBanner, setSuccessBanner] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Protected Targets Configuration (PROTECTED_TARGET_IPS)
  const [protectedTargets, setProtectedTargets] = useState([]);
  const [newTargetInput, setNewTargetInput] = useState('');
  const [savingTargets, setSavingTargets] = useState(false);

  // Advanced Interface Selection Toggle
  const [showAdvancedIfaces, setShowAdvancedIfaces] = useState(false);

  // Custom demo parameters
  const [customDemoOpen, setCustomDemoOpen] = useState(false);
  const [customPktCount, setCustomPktCount] = useState(350);
  const [customTargetIp, setCustomTargetIp] = useState('127.0.0.1');

  const pollIntervalRef = useRef(null);

  // 1. Initial Data Fetch
  const initializeMonitor = async () => {
    try {
      setLoading(true);
      setError(null);
      setDriverError(null);

      const [statusData, statsData, eventsData, activeData, ifacesData, driverData, targetsData] = await Promise.all([
        fetchIcmpStatus().catch(() => null),
        fetchIcmpStats().catch(() => null),
        fetchIcmpEvents({ limit: 15 }).catch(() => []),
        fetchActiveInterface().catch(() => null),
        fetchIcmpInterfaces(false).catch(() => []),
        fetchDriverStatus().catch(() => ({ available: false, message: '' })),
        fetchProtectedTargets().catch(() => null)
      ]);

      if (statusData) setStatus(statusData);
      if (statsData) setStats(statsData);
      setEvents(eventsData || []);
      if (activeData) {
        setActiveIface(activeData);
        setSelectedInterface(activeData.name || 'Wi-Fi');
      }
      setInterfaces(ifacesData || []);
      if (driverData) {
        setDriverStatus(driverData);
        if (!driverData.available) {
          setDriverError(driverData.message);
        }
      }

      if (targetsData?.protected_targets && targetsData.protected_targets.length > 0) {
        setProtectedTargets(targetsData.protected_targets);
        setCustomTargetIp(targetsData.protected_targets[0]);
      } else if (statusData?.protected_target_ips && statusData.protected_target_ips.length > 0) {
        setProtectedTargets(statusData.protected_target_ips);
        setCustomTargetIp(statusData.protected_target_ips[0]);
      }
    } catch (err) {
      setError(err.message || 'Failed to initialize ICMP monitoring service');
    } finally {
      setLoading(false);
    }
  };

  // Target Management Handlers
  const handleAddTarget = async (ipToAdd) => {
    const cleanIp = (ipToAdd || newTargetInput).trim();
    if (!cleanIp) return;
    if (protectedTargets.includes(cleanIp)) {
      setSuccessBanner(`Target ${cleanIp} is already in the protected targets list.`);
      setNewTargetInput('');
      return;
    }
    const updated = [...protectedTargets, cleanIp];
    setSavingTargets(true);
    try {
      const res = await updateProtectedTargets(updated);
      setProtectedTargets(res.protected_targets || updated);
      setNewTargetInput('');
      setSuccessBanner(`Protected target '${cleanIp}' registered. Incoming echo requests to this destination are now monitored.`);
      await pollTelemetry();
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to add protected target');
    } finally {
      setSavingTargets(false);
    }
  };

  const handleRemoveTarget = async (ipToRemove) => {
    const updated = protectedTargets.filter(t => t !== ipToRemove);
    setSavingTargets(true);
    try {
      const res = await updateProtectedTargets(updated);
      setProtectedTargets(res.protected_targets || updated);
      setSuccessBanner(`Protected target '${ipToRemove}' removed from inspection scope.`);
      await pollTelemetry();
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to remove protected target');
    } finally {
      setSavingTargets(false);
    }
  };

  // Toggle Advanced Adapters list
  const handleToggleAdvanced = async () => {
    const nextState = !showAdvancedIfaces;
    setShowAdvancedIfaces(nextState);
    try {
      const data = await fetchIcmpInterfaces(nextState);
      setInterfaces(data || []);
    } catch (err) {
      console.warn('Could not reload interfaces:', err);
    }
  };

  // 2. Real-time Telemetry Polling (every 1.5s)
  const pollTelemetry = async () => {
    try {
      const [statsData, eventsData] = await Promise.all([
        fetchIcmpStats(),
        fetchIcmpEvents({ limit: 15 })
      ]);
      if (statsData) {
        setStats(statsData);
        setStatus(statsData);
        if (statsData.protected_target_ips) {
          setProtectedTargets(statsData.protected_target_ips);
        }
      }
      if (eventsData) {
        setEvents(eventsData);
      }
    } catch (err) {
      console.warn('ICMP telemetry poll skipped:', err.message);
    }
  };

  useEffect(() => {
    initializeMonitor();
  }, []);

  useEffect(() => {
    if (autoRefresh) {
      pollIntervalRef.current = setInterval(pollTelemetry, 1500);
    } else if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
    }
    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  }, [autoRefresh]);

  useSocRefresh(pollTelemetry);

  // START REAL MONITORING
  const handleStartReal = async () => {
    setActionLoading(true);
    setError(null);
    setDriverError(null);
    setSuccessBanner(null);

    try {
      const res = await startIcmpMonitor(selectedInterface, protectedTargets);
      setStatus(res.data);
      setSuccessBanner(`Real ICMP packet capture active on interface '${res.data.interface}' protecting [${(res.data.protected_target_ips || protectedTargets).join(', ') || 'Host IP'}].`);
      await pollTelemetry();
    } catch (err) {
      const detail = err.response?.data?.detail || err.message;
      if (detail && detail.includes('Npcap')) {
        setDriverError(detail);
      } else {
        setError(detail || 'Failed to start real ICMP packet capture');
      }
    } finally {
      setActionLoading(false);
    }
  };

  // STOP REAL MONITORING
  const handleStopReal = async () => {
    setActionLoading(true);
    setError(null);
    setSuccessBanner(null);
    try {
      const res = await stopIcmpMonitor();
      setStatus(res.data);
      setSuccessBanner('Real ICMP packet monitoring stopped.');
      await pollTelemetry();
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to stop ICMP monitor');
    } finally {
      setActionLoading(false);
    }
  };

  // RESET TELEMETRY BUFFER
  const handleReset = async () => {
    setActionLoading(true);
    try {
      await resetIcmpStats();
      setSuccessBanner('Real packet counters and sliding window buffer cleared.');
      await pollTelemetry();
    } catch (err) {
      setError(err.message || 'Failed to reset statistics');
    } finally {
      setActionLoading(false);
    }
  };

  // ISOLATED DEMONSTRATION / SIMULATION (SECTION 11)
  const handleSimulate = async (scenario, count = null) => {
    setSimulating(true);
    setError(null);
    setSuccessBanner(null);
    try {
      const effectiveTarget = customTargetIp || (protectedTargets.length > 0 ? protectedTargets[0] : '127.0.0.1');
      const res = await simulateIcmpTraffic(scenario, {
        count: count || null,
        target_ip: effectiveTarget,
        attacker_ip: '192.168.1.185'
      });
      setSuccessBanner(
        `Simulation '${scenario.toUpperCase()}' completed (${res.packets_generated} synthetic packets directed to protected target ${effectiveTarget}). Alert created in Supabase. [Mode: ${res.mode}]`
      );
      await pollTelemetry();
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Simulation execution failed');
    } finally {
      setSimulating(false);
    }
  };

  if (loading && !status) {
    return <LoadingSpinner message="Connecting to Live ICMP Monitoring Subsystem..." />;
  }

  const isRunning = status?.is_running === true;
  const detectionState = status?.detection_state || 'NORMAL';
  const history = stats?.history || [];
  const pps = status?.current_rate_pps ?? 0;
  const observed = status?.packets_observed ?? 0;
  const activeWindow = status?.active_window_packets ?? 0;
  const uniqueSources = status?.unique_sources ?? 0;
  const windowSeconds = status?.window_seconds ?? 10;
  const ifaceName = status?.interface || activeIface?.name || 'Wi-Fi';
  const ifaceIp = status?.interface_ip || activeIface?.ip || '10.171.83.105';
  const thresholds = status?.thresholds || {
    suspicious_threshold: 100,
    dos_threshold: 300,
    ddos_threshold: 500,
    unique_source_threshold: 10
  };

  return (
    <div className="space-y-8">
      
      {/* 1. Header & Main Controls Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl border ${
              isRunning 
                ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400 animate-pulse' 
                : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
            }`}>
              <Radio className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-3 flex-wrap">
                <h1 className="text-xl sm:text-2xl font-bold text-white tracking-wide">
                  Real-time ICMP Monitoring
                </h1>
                
                {/* Status Badge (Section 10) */}
                {isRunning ? (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/40 shadow-sm shadow-emerald-950">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping" />
                    REAL CAPTURE ACTIVE
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-semibold bg-gray-800 text-slate-400 border border-gray-700">
                    <span className="w-2 h-2 rounded-full bg-slate-500" />
                    MONITORING STOPPED
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Defensive live packet capture, sliding-window analysis, and DoS/DDoS threat detection.
              </p>
            </div>
          </div>
        </div>

        {/* Live Action Controls */}
        <div className="flex flex-wrap items-center gap-2 sm:gap-3">
          
          {/* Start / Stop Real Monitoring Button */}
          {isRunning ? (
            <button
              onClick={handleStopReal}
              disabled={actionLoading}
              className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-red-500/15 hover:bg-red-500/25 border border-red-500/40 text-red-400 text-xs font-mono font-semibold transition shadow-sm"
              title="Stop active real packet capture"
            >
              <Square className="w-4 h-4 fill-red-400" />
              <span>{actionLoading ? 'Stopping...' : 'Stop Monitoring'}</span>
            </button>
          ) : (
            <button
              onClick={handleStartReal}
              disabled={actionLoading}
              className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/40 text-emerald-400 text-xs font-mono font-semibold transition shadow-sm"
              title="Begin capturing real ICMP packets from active network interface"
            >
              <Play className="w-4 h-4 fill-emerald-400" />
              <span>{actionLoading ? 'Starting...' : 'Start Monitoring'}</span>
            </button>
          )}

          {/* Reset Stats */}
          <button
            onClick={handleReset}
            disabled={actionLoading}
            className="p-2 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-slate-400 hover:text-white transition"
            title="Reset real packet counters and sliding window buffer"
          >
            <RotateCcw className="w-4 h-4" />
          </button>

          {/* Polling Toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`inline-flex items-center space-x-1.5 px-3 py-2 rounded-lg border text-xs font-mono font-medium transition ${
              autoRefresh 
                ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400' 
                : 'bg-gray-900 border-gray-800 text-slate-400'
            }`}
            title="Toggle live telemetry polling"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${autoRefresh ? 'animate-spin' : ''}`} />
            <span>{autoRefresh ? 'Live Poll (1.5s)' : 'Poll Paused'}</span>
          </button>
        </div>
      </div>

      {/* Driver Warning Banner (Section 2 & 12) */}
      {driverError && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/40 text-amber-300 text-xs font-mono space-y-2">
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
            <div className="space-y-1">
              <span className="font-bold text-amber-200 uppercase tracking-wide">
                Packet Capture Driver Notice:
              </span>
              <p className="text-amber-300/90 leading-relaxed">
                {driverError}
              </p>
              <p className="text-[11px] text-slate-400">
                To enable live NIC packet capture on Windows, download and install Npcap from{' '}
                <a 
                  href="https://npcap.com/#download" 
                  target="_blank" 
                  rel="noreferrer" 
                  className="text-cyan-400 underline hover:text-cyan-300"
                >
                  https://npcap.com
                </a>
                . Meanwhile, you can test detection rules, Supabase alerts, and dashboard reactivity using the{' '}
                <span className="font-semibold text-white">Local Test / Simulation</span> console below.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* General Error Banner */}
      {error && <ErrorMessage message={error} onDismiss={() => setError(null)} />}
      
      {/* Success Notification */}
      {successBanner && (
        <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>{successBanner}</span>
          </div>
          <button onClick={() => setSuccessBanner(null)} className="text-emerald-400 hover:text-white ml-2">×</button>
        </div>
      )}

      {/* =========================================================================
          2. REAL METRIC SUMMARY CARDS (SECTION 4 & 10)
          Values represent ONLY actual captured packets, NOT synthetic simulations!
          ========================================================================= */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        
        {/* Card 1: Active Interface */}
        <div className="p-5 rounded-xl soc-glass border border-gray-800 flex flex-col justify-between relative group">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 uppercase">Active Interface</span>
              <Network className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-lg font-bold text-white mt-1 truncate" title={ifaceName}>
              {ifaceName}
            </div>
            <div className="text-xs font-mono text-cyan-400 font-semibold mt-0.5">
              {ifaceIp}
            </div>
          </div>
          <div className="mt-3 pt-3 border-t border-gray-800/80 text-[10px] font-mono text-slate-400 flex items-center gap-1">
            <Info className="w-3 h-3 text-cyan-400 flex-shrink-0" />
            <span title="The interface is the network connection from which the SOC captures packets.">
              Primary network connection
            </span>
          </div>
        </div>

        {/* Card 2: Current ICMP Rate (pps) */}
        <div className="p-5 rounded-xl soc-glass border border-gray-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 uppercase">Current ICMP Rate</span>
              <Activity className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white mt-1 flex items-baseline gap-1.5">
              <span>{pps}</span>
              <span className="text-xs font-mono text-slate-400 font-normal">packets/sec</span>
            </div>
          </div>
          <div className="mt-3 pt-3 border-t border-gray-800/80 flex items-center justify-between text-[11px] font-mono">
            <span className="text-slate-400">Sliding Window:</span>
            <span className="text-slate-300">{windowSeconds}s ({activeWindow} pkts)</span>
          </div>
        </div>

        {/* Card 3: Packets Observed */}
        <div className="p-5 rounded-xl soc-glass border border-gray-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 uppercase">Packets Observed</span>
              <Cpu className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-white mt-1">
              {observed.toLocaleString()}
            </div>
          </div>
          <div className="mt-3 pt-3 border-t border-gray-800/80 flex items-center justify-between text-[11px] font-mono">
            <span className="text-slate-400">Mode:</span>
            <span className="text-emerald-400 font-semibold uppercase">{isRunning ? 'REAL PACKET STREAM' : 'STANDBY'}</span>
          </div>
        </div>

        {/* Card 4: Unique Sources */}
        <div className="p-5 rounded-xl soc-glass border border-gray-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 uppercase">Unique Source IPs</span>
              <Radio className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold text-white mt-1">
              {uniqueSources}
            </div>
          </div>
          <div className="mt-3 pt-3 border-t border-gray-800/80 flex items-center justify-between text-[11px] font-mono">
            <span className="text-slate-400">DDoS Diversity:</span>
            <span className="text-amber-400 font-semibold">&gt;= {thresholds.unique_source_threshold} IPs</span>
          </div>
        </div>

        {/* Card 5: Real Detection State */}
        <div className="p-5 rounded-xl soc-glass border border-gray-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 uppercase">Threat Status</span>
              <ShieldAlert className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-sm font-bold mt-1">
              {detectionState === 'POSSIBLE_DDOS' && <span className="text-purple-400">🔴 POSSIBLE DDOS</span>}
              {detectionState === 'POSSIBLE_DOS' && <span className="text-red-400">🔴 POSSIBLE DOS</span>}
              {detectionState === 'SUSPICIOUS' && <span className="text-amber-400">🟡 SUSPICIOUS</span>}
              {detectionState === 'NORMAL' && <span className="text-emerald-400">🟢 NORMAL</span>}
            </div>
          </div>
          <div className="mt-3 pt-3 border-t border-gray-800/80 flex items-center justify-between text-[11px] font-mono">
            <span className="text-slate-400">Category:</span>
            <span className="text-cyan-400">Network Availability</span>
          </div>
        </div>
      </div>

      {/* =========================================================================
          2B. TRAFFIC CLASSIFICATION & DIRECTIONAL SEGREGATION
          Incoming requests to protected targets are counted separately from outgoing pings (e.g. 8.8.8.8)
          ========================================================================= */}
      <div className="p-5 rounded-xl soc-glass border border-gray-800 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-gray-800/80 pb-3">
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-bold text-white uppercase font-mono tracking-wider">
              Traffic Classification &amp; Directional Segregation
            </h3>
          </div>
          <span className="text-[10px] font-mono text-slate-400">
            Pinging 8.8.8.8 or external hosts is classified as Egress and strictly excluded from DoS alerts
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* 1. Protected Inbound Requests */}
          <div className="p-3.5 rounded-lg bg-emerald-500/5 border border-emerald-500/30">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono font-semibold text-emerald-400 flex items-center gap-1.5">
                <Target className="w-3.5 h-3.5" />
                Protected Inbound Requests
              </span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold">
                EVALUATED
              </span>
            </div>
            <div className="text-xl font-bold text-white mt-1.5 flex items-baseline gap-1.5">
              <span>{(status?.total_protected_incoming_observed ?? 0).toLocaleString()}</span>
              <span className="text-[10px] font-mono text-slate-400 font-normal">
                ({status?.protected_incoming_requests ?? 0} active)
              </span>
            </div>
            <p className="text-[10px] font-mono text-emerald-300/80 mt-1">
              Echo requests directed to protected IP(s). Triggers RULE_06 &amp; RULE_07.
            </p>
          </div>

          {/* 2. Outgoing Requests (Egress) */}
          <div className="p-3.5 rounded-lg bg-sky-500/5 border border-sky-500/20">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono font-semibold text-sky-400 flex items-center gap-1.5">
                <ArrowUpRight className="w-3.5 h-3.5" />
                Outgoing Requests (Egress)
              </span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-sky-500/20 text-sky-300 border border-sky-500/30">
                EXCLUDED
              </span>
            </div>
            <div className="text-xl font-bold text-white mt-1.5 flex items-baseline gap-1.5">
              <span>{(status?.total_outgoing_observed ?? 0).toLocaleString()}</span>
              <span className="text-[10px] font-mono text-slate-400 font-normal">
                ({status?.outgoing_requests ?? 0} active)
              </span>
            </div>
            <p className="text-[10px] font-mono text-slate-400 mt-1">
              Pings initiated by this host (e.g. to 8.8.8.8). Will NOT alert.
            </p>
          </div>

          {/* 3. Echo Replies (Pong) */}
          <div className="p-3.5 rounded-lg bg-gray-900/60 border border-gray-800">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono font-semibold text-slate-300 flex items-center gap-1.5">
                <ArrowDownLeft className="w-3.5 h-3.5 text-slate-400" />
                Echo Replies (Type 0)
              </span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-gray-800 text-slate-400 border border-gray-700">
                EXCLUDED
              </span>
            </div>
            <div className="text-xl font-bold text-white mt-1.5 flex items-baseline gap-1.5">
              <span>{(status?.total_replies_observed ?? 0).toLocaleString()}</span>
              <span className="text-[10px] font-mono text-slate-400 font-normal">
                ({status?.replies_observed ?? 0} active)
              </span>
            </div>
            <p className="text-[10px] font-mono text-slate-400 mt-1">
              Pong responses to queries. Excluded from flood calculation.
            </p>
          </div>

          {/* 4. Unrelated Destinations */}
          <div className="p-3.5 rounded-lg bg-gray-900/60 border border-gray-800">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono font-semibold text-slate-300 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-slate-400" />
                Unrelated Destinations
              </span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-gray-800 text-slate-400 border border-gray-700">
                EXCLUDED
              </span>
            </div>
            <div className="text-xl font-bold text-white mt-1.5 flex items-baseline gap-1.5">
              <span>{(status?.total_unrelated_observed ?? 0).toLocaleString()}</span>
              <span className="text-[10px] font-mono text-slate-400 font-normal">
                ({status?.unrelated_packets ?? 0} active)
              </span>
            </div>
            <p className="text-[10px] font-mono text-slate-400 mt-1">
              Packets destined to IPs outside PROTECTED_TARGET_IPS list.
            </p>
          </div>
        </div>
      </div>

      {/* =========================================================================
          2C. SENSOR PLACEMENT & NETWORK VISIBILITY ADVISORY
          Explains why a personal laptop physically cannot observe remote target traffic
          ========================================================================= */}
      {status?.sensor_info?.sensor_mode === 'REMOTE_TARGET' ? (
        <div className="p-5 rounded-xl bg-amber-500/10 border border-amber-500/40 text-amber-200 text-xs font-mono space-y-2">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="font-bold text-amber-200 uppercase tracking-wide">
                  Sensor Placement Advisory — Remote Target Visibility Notice
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                  REMOTE TARGET CONFIGURED
                </span>
              </div>
              <p className="text-amber-300/90 leading-relaxed text-[11px]">
                {status.sensor_info.visibility_explanation}
              </p>
              <div className="p-3 rounded-lg bg-black/40 border border-amber-500/30 text-[11px] text-slate-300 space-y-1.5">
                <div className="font-bold text-amber-300 flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5" />
                  Required Sensor Architecture for Remote Websites / Servers:
                </div>
                <ul className="list-disc list-inside space-y-1 text-slate-300 pl-1">
                  <li>
                    <strong className="text-white">Host-Based Deployment:</strong> Install and run this AI SOC Copilot detector directly on the protected server (Linux/Windows VPS, cloud instance, or container) where incoming traffic terminates.
                  </li>
                  <li>
                    <strong className="text-white">Authorized Network Sensor:</strong> Deploy on a server or appliance attached to an inline hardware TAP or switch SPAN / mirror port at the protected server&apos;s perimeter gateway.
                  </li>
                  <li>
                    <strong className="text-white">Safe Local Testing:</strong> You can test RULE_06 (DoS) and RULE_07 (DDoS) detection against this target using the <span className="text-amber-300 font-semibold">Local Test / Simulation</span> console below.
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-4 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-200 text-xs font-mono">
          <div className="flex items-start gap-2.5">
            <ShieldCheck className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
            <div className="space-y-0.5">
              <span className="font-bold text-cyan-300 uppercase tracking-wide">
                Host-Based Sensor Mode Active
              </span>
              <p className="text-[11px] text-slate-300">
                Observing inbound ICMP traffic arriving directly at this machine&apos;s local network interface ({ifaceName} — {ifaceIp}). Echo requests sent to protected target(s) [{(protectedTargets.length > 0 ? protectedTargets : [ifaceIp]).join(', ')}] will be analyzed in real time.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          2D. PROTECTED TARGET CONFIGURATION (PROTECTED_TARGET_IPS)
          Configures target destination IPs to scope DoS/DDoS detection
          ========================================================================= */}
      <div className="p-5 rounded-xl soc-glass border border-gray-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-gray-800/80 pb-3">
          <div className="flex items-start gap-3">
            <Target className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-xs font-bold text-white uppercase font-mono tracking-wider">
                  Protected Destination IPs (PROTECTED_TARGET_IPS)
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-semibold">
                  TARGET-FILTERED
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Only incoming ICMP echo requests directed to these protected destination IPs are analyzed for DoS/DDoS thresholding. Outgoing pings (e.g. to 8.8.8.8) and non-matching traffic are excluded from alerts.
              </p>
            </div>
          </div>
        </div>

        {/* Target Chips & Editor */}
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-mono text-slate-400">Active Targets:</span>
            {protectedTargets.length === 0 ? (
              <span className="text-xs font-mono text-amber-400/90 italic">
                None configured (Defaulting to host IP {ifaceIp})
              </span>
            ) : (
              protectedTargets.map((target) => (
                <span 
                  key={target} 
                  className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-800 shadow-sm"
                >
                  <Target className="w-3 h-3 text-cyan-400" />
                  <span>{target}</span>
                  <button
                    type="button"
                    onClick={() => handleRemoveTarget(target)}
                    disabled={savingTargets}
                    className="ml-1 text-slate-400 hover:text-red-400 transition"
                    title={`Remove ${target} from protected targets`}
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </span>
              ))
            )}
          </div>

          {/* Target Input & Quick Presets */}
          <div className="flex flex-wrap items-center gap-3 pt-1">
            <div className="flex items-center gap-2 flex-1 min-w-[260px] max-w-md">
              <input
                type="text"
                value={newTargetInput}
                onChange={(e) => setNewTargetInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleAddTarget()}
                placeholder="e.g. 192.168.1.100 or server IP"
                className="w-full px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              />
              <button
                type="button"
                onClick={() => handleAddTarget()}
                disabled={savingTargets || !newTargetInput.trim()}
                className="px-3 py-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/40 text-cyan-400 text-xs font-mono font-semibold transition disabled:opacity-50 whitespace-nowrap"
              >
                {savingTargets ? 'Updating...' : 'Add Target'}
              </button>
            </div>

            {/* Quick Presets */}
            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="text-slate-500 text-[11px]">Quick Add:</span>
              <button
                type="button"
                onClick={() => handleAddTarget(ifaceIp)}
                disabled={savingTargets || protectedTargets.includes(ifaceIp)}
                className="px-2.5 py-1 rounded bg-gray-900 hover:bg-gray-800 border border-gray-800 text-slate-400 hover:text-cyan-400 text-[11px] transition disabled:opacity-40"
              >
                + Host IP ({ifaceIp})
              </button>
              <button
                type="button"
                onClick={() => handleAddTarget('127.0.0.1')}
                disabled={savingTargets || protectedTargets.includes('127.0.0.1')}
                className="px-2.5 py-1 rounded bg-gray-900 hover:bg-gray-800 border border-gray-800 text-slate-400 hover:text-cyan-400 text-[11px] transition disabled:opacity-40"
              >
                + Localhost (127.0.0.1)
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* =========================================================================
          3. NETWORK INTERFACE CONFIGURATION (SECTION 3)
          ========================================================================= */}
      <div className="p-5 rounded-xl soc-glass border border-gray-800 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-start gap-3">
            <Network className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-xs font-bold text-white uppercase font-mono tracking-wider">
                  Network Interface Configuration
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950/80 text-cyan-300 border border-cyan-800">
                  AUTO-SELECTED ACTIVE ADAPTER
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5" title="The interface is the network connection from which the SOC captures packets.">
                The interface is the network connection from which the SOC captures packets.
              </p>
            </div>
          </div>

          {/* Adapter Selection Controls */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <label htmlFor="active-iface-select" className="text-xs font-mono text-slate-400">Interface:</label>
              <select
                id="active-iface-select"
                value={selectedInterface}
                disabled={isRunning || actionLoading}
                onChange={(e) => setSelectedInterface(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-xs font-mono text-white focus:outline-none focus:border-cyan-500 disabled:opacity-60 cursor-pointer min-w-[200px]"
              >
                {interfaces.map((iface) => (
                  <option key={iface.id || iface.name} value={iface.name || iface.id}>
                    {iface.name} {iface.ip ? `— ${iface.ip}` : ''}
                  </option>
                ))}
              </select>
            </div>

            {/* Advanced Selection Toggle */}
            <button
              onClick={handleToggleAdvanced}
              className="inline-flex items-center space-x-1 px-2.5 py-1.5 rounded bg-gray-900 hover:bg-gray-800 border border-gray-800 text-[11px] font-mono text-slate-400 hover:text-cyan-400 transition"
              title="Toggle advanced view to reveal low-level / virtual network adapters"
            >
              <span>{showAdvancedIfaces ? 'Hide Advanced' : 'Advanced Interface Selection'}</span>
              {showAdvancedIfaces ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>
          </div>
        </div>

        {isRunning && (
          <p className="text-[10px] font-mono text-slate-500 italic">
            * Packet capture is actively running. Stop monitoring to switch adapters.
          </p>
        )}
      </div>

      {/* =========================================================================
          4. REAL-TIME LIVE ICMP GRAPH (SECTION 16)
          ========================================================================= */}
      <div className="p-6 rounded-xl soc-glass border border-gray-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white tracking-wide">Real ICMP Traffic Telemetry</h3>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Time (HH:MM:SS) → Real Packets/sec with deterministic DoS &amp; Suspicious threshold references
            </p>
          </div>

          {/* Legend Badges */}
          <div className="flex items-center gap-3 text-[11px] font-mono">
            <span className="flex items-center gap-1.5 text-cyan-400">
              <span className="w-2.5 h-2.5 rounded-sm bg-cyan-500 inline-block" />
              Real ICMP Rate (pps)
            </span>
            <span className="flex items-center gap-1.5 text-amber-400">
              <span className="w-2.5 h-0.5 bg-amber-400 inline-block" />
              Suspicious ({thresholds.suspicious_threshold / windowSeconds} pps)
            </span>
            <span className="flex items-center gap-1.5 text-red-400">
              <span className="w-2.5 h-0.5 bg-red-400 inline-block" />
              DoS Limit ({thresholds.dos_threshold / windowSeconds} pps)
            </span>
          </div>
        </div>

        {/* Chart Container */}
        <div className="h-72 w-full pt-4">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={history} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="realIcmpRateGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop 
                    offset="5%" 
                    stopColor={detectionState === 'POSSIBLE_DOS' || detectionState === 'POSSIBLE_DDOS' ? '#EF4444' : '#06B6D4'} 
                    stopOpacity={0.4} 
                  />
                  <stop 
                    offset="95%" 
                    stopColor={detectionState === 'POSSIBLE_DOS' || detectionState === 'POSSIBLE_DDOS' ? '#EF4444' : '#06B6D4'} 
                    stopOpacity={0.0} 
                  />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={chartColors.gridStroke} vertical={false} />
              <XAxis 
                dataKey="time" 
                stroke={chartColors.axisStroke} 
                fontSize={11} 
                tickLine={false}
                axisLine={{ stroke: chartColors.gridStroke }}
              />
              <YAxis 
                stroke={chartColors.axisStroke} 
                fontSize={11} 
                tickLine={false}
                axisLine={{ stroke: chartColors.gridStroke }}
              />
              <Tooltip 
                contentStyle={{
                  backgroundColor: chartColors.tooltipBg,
                  borderColor: chartColors.tooltipBorder,
                  borderRadius: '0.5rem',
                  fontSize: '12px',
                  color: chartColors.tooltipText,
                  fontFamily: 'monospace'
                }}
                formatter={(val) => [`${val} pps`, 'Real ICMP Rate']}
              />
              
              {/* Suspicious Threshold Reference Line */}
              <ReferenceLine 
                y={thresholds.suspicious_threshold / windowSeconds} 
                stroke="#F59E0B" 
                strokeDasharray="4 4" 
                label={{ value: 'Suspicious Threshold', fill: '#F59E0B', fontSize: 10, position: 'right' }} 
              />
              
              {/* DoS Threshold Reference Line */}
              <ReferenceLine 
                y={thresholds.dos_threshold / windowSeconds} 
                stroke="#EF4444" 
                strokeDasharray="4 4" 
                label={{ value: 'DoS Threshold', fill: '#EF4444', fontSize: 10, position: 'right' }} 
              />

              <Area 
                type="monotone" 
                dataKey="pps" 
                stroke={detectionState === 'POSSIBLE_DOS' || detectionState === 'POSSIBLE_DDOS' ? '#EF4444' : '#06B6D4'} 
                strokeWidth={2}
                fillOpacity={1} 
                fill="url(#realIcmpRateGradient)" 
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* =========================================================================
          5. LOCAL TEST / SIMULATION SECTION (SECTION 1, 8, 11)
          Visually isolated and labeled: "SIMULATION — NOT LIVE PACKET CAPTURE"
          ========================================================================= */}
      <div className="p-6 rounded-xl soc-glass border border-dashed border-amber-500/40 bg-amber-950/5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-start gap-2.5">
            <div className="p-1.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/30 mt-0.5">
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-bold text-white tracking-wide">Local Test / Simulation</h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                  SIMULATION — NOT LIVE PACKET CAPTURE
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Verify that RULE_06 and RULE_07 create alerts, update the SOC dashboard, and persist to Supabase PostgreSQL without generating uncontrolled external network floods.
              </p>
            </div>
          </div>

          <button
            onClick={() => setCustomDemoOpen(!customDemoOpen)}
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-xs font-mono text-slate-300 hover:text-white self-start sm:self-auto"
          >
            <Sliders className="w-3.5 h-3.5 text-amber-400" />
            <span>{customDemoOpen ? 'Hide Options' : 'Custom Options'}</span>
          </button>
        </div>

        {/* Custom Parameters Drawer */}
        {customDemoOpen && (
          <div className="p-4 rounded-lg bg-gray-900/80 border border-gray-800 grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <label htmlFor="sim-target-ip" className="text-slate-400 block mb-1">Target Destination IP:</label>
              <input 
                id="sim-target-ip"
                type="text" 
                value={customTargetIp} 
                onChange={(e) => setCustomTargetIp(e.target.value)}
                className="w-full px-3 py-1.5 rounded bg-black/40 border border-gray-700 text-white focus:outline-none focus:border-amber-500"
                placeholder="127.0.0.1 or local VM"
              />
            </div>
            <div>
              <label htmlFor="sim-packet-count" className="text-slate-400 block mb-1">DoS Volume (Packets):</label>
              <input 
                id="sim-packet-count"
                type="number" 
                value={customPktCount} 
                onChange={(e) => setCustomPktCount(parseInt(e.target.value) || 350)}
                className="w-full px-3 py-1.5 rounded bg-black/40 border border-gray-700 text-white focus:outline-none focus:border-amber-500"
                min="10"
                max="2000"
              />
            </div>
          </div>
        )}

        {/* 4 Demonstration Buttons */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-1">
          
          {/* STEP 1: Normal Traffic */}
          <button
            onClick={() => handleSimulate('normal', 15)}
            disabled={simulating}
            className="p-3.5 rounded-lg bg-gray-900/90 hover:bg-gray-800/90 border border-gray-800 hover:border-emerald-500/40 text-left transition flex flex-col justify-between group"
          >
            <div>
              <span className="text-[10px] font-mono text-emerald-400 font-semibold uppercase">Step 1 • Baseline</span>
              <div className="font-bold text-xs text-white mt-1 group-hover:text-emerald-300">
                🟢 Baseline Normal
              </div>
              <p className="text-[11px] text-slate-400 font-mono mt-1">15 packets (1.5 pps)</p>
            </div>
            <div className="mt-3 text-[10px] font-mono text-slate-500 flex items-center justify-between">
              <span>State: NORMAL</span>
              <span className="text-emerald-400 font-bold">Inject →</span>
            </div>
          </button>

          {/* STEP 2: Suspicious Traffic */}
          <button
            onClick={() => handleSimulate('suspicious', 120)}
            disabled={simulating}
            className="p-3.5 rounded-lg bg-gray-900/90 hover:bg-gray-800/90 border border-gray-800 hover:border-amber-500/40 text-left transition flex flex-col justify-between group"
          >
            <div>
              <span className="text-[10px] font-mono text-amber-400 font-semibold uppercase">Step 2 • Elevated</span>
              <div className="font-bold text-xs text-white mt-1 group-hover:text-amber-300">
                🟡 Suspicious Activity
              </div>
              <p className="text-[11px] text-slate-400 font-mono mt-1">120 packets (12.0 pps)</p>
            </div>
            <div className="mt-3 text-[10px] font-mono text-slate-500 flex items-center justify-between">
              <span>State: SUSPICIOUS</span>
              <span className="text-amber-400 font-bold">Inject →</span>
            </div>
          </button>

          {/* STEP 3: Possible ICMP DoS */}
          <button
            onClick={() => handleSimulate('dos', customPktCount)}
            disabled={simulating}
            className="p-3.5 rounded-lg bg-gray-900/90 hover:bg-gray-800/90 border border-gray-800 hover:border-red-500/40 text-left transition flex flex-col justify-between group"
          >
            <div>
              <span className="text-[10px] font-mono text-red-400 font-semibold uppercase">Step 3 • Single Source</span>
              <div className="font-bold text-xs text-white mt-1 group-hover:text-red-300">
                🔴 Possible ICMP DoS
              </div>
              <p className="text-[11px] text-slate-400 font-mono mt-1">{customPktCount} pkts • RULE_06</p>
            </div>
            <div className="mt-3 text-[10px] font-mono text-slate-500 flex items-center justify-between">
              <span className="text-red-400 font-semibold">Creates High Alert</span>
              <span className="text-red-400 font-bold">Inject →</span>
            </div>
          </button>

          {/* STEP 4: Possible ICMP DDoS (Section 8: Labeled Simulated Distributed Traffic) */}
          <button
            onClick={() => handleSimulate('ddos', 600)}
            disabled={simulating}
            className="p-3.5 rounded-lg bg-gray-900/90 hover:bg-gray-800/90 border border-gray-800 hover:border-purple-500/40 text-left transition flex flex-col justify-between group"
          >
            <div>
              <span className="text-[10px] font-mono text-purple-400 font-semibold uppercase">Step 4 • Multi-Source</span>
              <div className="font-bold text-xs text-white mt-1 group-hover:text-purple-300">
                🟣 Simulated Distributed (DDoS)
              </div>
              <p className="text-[11px] text-slate-400 font-mono mt-1">600 pkts • Demo Only</p>
            </div>
            <div className="mt-3 text-[10px] font-mono text-slate-500 flex items-center justify-between">
              <span className="text-purple-400 font-semibold">Creates Critical Alert</span>
              <span className="text-purple-400 font-bold">Inject →</span>
            </div>
          </button>
        </div>
      </div>

      {/* =========================================================================
          6. LIVE SECURITY ALERTS STREAM (SECTION 7 & 17)
          ========================================================================= */}
      <div className="p-6 rounded-xl soc-glass border border-gray-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              <h3 className="text-sm font-bold text-white tracking-wide">Recent ICMP Security Alerts</h3>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Correlated alerts dispatched directly to the central SOC console &amp; Supabase PostgreSQL
            </p>
          </div>
          
          <Link
            to="/alerts"
            className="inline-flex items-center space-x-1 text-xs font-mono text-cyan-400 hover:text-cyan-300 transition"
          >
            <span>View All SOC Alerts</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </Link>
        </div>

        {events.length === 0 ? (
          <EmptyState 
            title="No ICMP Anomaly Events Recorded"
            message="Traffic is currently within normal threshold limits. Generate traffic or execute simulation above."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="border-b border-gray-800 text-slate-400 bg-gray-900/40">
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Title / Detection</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Source IP</th>
                  <th className="py-2.5 px-3">Target IP</th>
                  <th className="py-2.5 px-3 text-right">Volume</th>
                  <th className="py-2.5 px-3 text-right">Type</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60">
                {events.map((ev, index) => {
                  const isSim = ev.is_simulation || ev.title?.includes('[SIMULATION]');
                  return (
                    <tr key={ev.id || index} className="hover:bg-gray-800/30 transition">
                      <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                        {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'Just now'}
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="font-semibold text-white">{ev.title}</div>
                        <span className="text-[10px] text-cyan-400">{ev.detection_type}</span>
                      </td>
                      <td className="py-2.5 px-3">
                        <SeverityBadge severity={ev.severity || 'HIGH'} />
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">{ev.source_ip || '127.0.0.1'}</td>
                      <td className="py-2.5 px-3 text-slate-300">{ev.destination_ip || '127.0.0.1'}</td>
                      <td className="py-2.5 px-3 text-right font-bold text-white">
                        {ev.packet_count ?? 350} pkts
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        {isSim ? (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/30">
                            DEMO
                          </span>
                        ) : (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold">
                            REAL
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
}
