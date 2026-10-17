import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  Activity, 
  AlertTriangle, 
  ShieldAlert, 
  Globe, 
  ExternalLink,
  ShieldCheck,
  RefreshCw,
  Layers
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell, 
  Tooltip as RechartsTooltip, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  BarChart, 
  Bar 
} from 'recharts';
import { fetchDashboardStats, fetchAlerts } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';
import EmptyState from '../components/EmptyState';
import SimulatorControls from '../components/SimulatorControls';
import { useTheme } from '../context/ThemeContext';
import { useSocRefresh } from '../context/SocRefreshContext';

export default function DashboardPage() {
  const { chartColors } = useTheme();
  const [stats, setStats] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadDashboardData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsData, alertsData] = await Promise.all([
        fetchDashboardStats(),
        fetchAlerts({ page: 1, limit: 6 })
      ]);
      setStats(statsData);
      setRecentAlerts(alertsData.items || []);
    } catch (err) {
      setError(err.message || 'Failed to load dashboard metrics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
    const timer = setInterval(loadDashboardData, 30000);
    return () => clearInterval(timer);
  }, []);

  useSocRefresh(loadDashboardData);

  if (loading && !stats) {
    return <LoadingSpinner message="Aggregating live SOC telemetry from PostgreSQL..." />;
  }

  if (error && !stats) {
    return <ErrorMessage message={error} onRetry={loadDashboardData} />;
  }

  const metrics = stats?.metrics || {
    total_events: 0,
    total_alerts: 0,
    critical_alerts: 0,
    open_incidents: 0,
    high_risk_ips: 0
  };

  const severityData = stats?.severity_distribution || [];
  const topIps = stats?.top_source_ips || [];
  const timeline = stats?.timeline || [];

  return (
    <div className="space-y-8">
      
      {/* Top Welcome & Refresh */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide">SOC Overview & Threat Analytics</h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Live telemetry, threat indicators, and rule-based detections.
          </p>
        </div>
        <button
          onClick={loadDashboardData}
          className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-cyan-400 text-xs font-mono font-medium transition self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Sync Analytics</span>
        </button>
      </div>

      {/* Attack Scenario Simulator Controls (Phase 4) */}
      <SimulatorControls onSimulationComplete={loadDashboardData} />

      {/* 4 Metric Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        
        {/* Total Ingested Events */}
        <div className="p-5 rounded-xl soc-glass border border-gray-800 flex items-center justify-between">
          <div>
            <span className="text-xs font-mono text-slate-400 uppercase">Total Events</span>
            <div className="text-2xl font-bold text-white mt-1">{metrics.total_events}</div>
            <span className="text-[10px] text-cyan-400 font-mono">Canonical Normalized</span>
          </div>
          <div className="p-3 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Activity className="w-6 h-6" />
          </div>
        </div>

        {/* Total Alerts */}
        <div className="p-5 rounded-xl soc-glass border border-gray-800 flex items-center justify-between">
          <div>
            <span className="text-xs font-mono text-slate-400 uppercase">Total Alerts</span>
            <div className="text-2xl font-bold text-white mt-1">{metrics.total_alerts}</div>
            <span className="text-[10px] text-amber-400 font-mono">Detections Triggered</span>
          </div>
          <div className="p-3 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle className="w-6 h-6" />
          </div>
        </div>

        {/* Critical Alerts */}
        <div className="p-5 rounded-xl soc-glass border border-gray-800 flex items-center justify-between">
          <div>
            <span className="text-xs font-mono text-slate-400 uppercase">Critical Severity</span>
            <div className="text-2xl font-bold text-red-400 mt-1">{metrics.critical_alerts}</div>
            <span className="text-[10px] text-red-400/80 font-mono">Immediate Triage</span>
          </div>
          <div className="p-3 rounded-xl bg-red-500/10 text-red-400 border border-red-500/20">
            <ShieldAlert className="w-6 h-6" />
          </div>
        </div>

        {/* Open Incidents */}
        <div className="p-5 rounded-xl soc-glass border border-gray-800 flex items-center justify-between">
          <div>
            <span className="text-xs font-mono text-slate-400 uppercase">Open Incidents</span>
            <div className="text-2xl font-bold text-purple-400 mt-1">{metrics.open_incidents}</div>
            <span className="text-[10px] text-purple-400/80 font-mono">Active Correlated</span>
          </div>
          <div className="p-3 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <Layers className="w-6 h-6" />
          </div>
        </div>

      </div>

      {/* Analytics Visualizations Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Severity Distribution Donut */}
        <div className="p-5 rounded-xl soc-glass border border-gray-800 space-y-3 flex flex-col">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Alert Severity Breakdown</h3>
            <span className="text-[10px] font-mono text-slate-400">By Severity</span>
          </div>

          <div className="h-56 w-full flex-1 flex items-center justify-center">
            {severityData.every(d => d.value === 0) ? (
              <div className="text-xs font-mono text-slate-500 text-center">
                No alerts detected yet
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip 
                    contentStyle={{ 
                      backgroundColor: chartColors.tooltipBg, 
                      borderColor: chartColors.tooltipBorder, 
                      color: chartColors.tooltipText,
                      borderRadius: '8px', 
                      fontSize: '12px' 
                    }} 
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Legend */}
          <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-2 border-t border-gray-800">
            {severityData.map((item) => (
              <div key={item.name} className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: item.color }} />
                <span className="text-slate-400">{item.name}:</span>
                <span className="text-white font-semibold">{item.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Source IPs Bar Chart */}
        <div className="p-5 rounded-xl soc-glass border border-gray-800 space-y-3 flex flex-col">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Top Offending Source IPs</h3>
            <Globe className="w-4 h-4 text-cyan-400" />
          </div>

          <div className="h-56 w-full flex-1 flex items-center justify-center">
            {topIps.length === 0 ? (
              <div className="text-xs font-mono text-slate-500 text-center">
                No IP telemetry recorded
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topIps} layout="vertical" margin={{ left: 20, right: 20, top: 10, bottom: 10 }}>
                  <XAxis type="number" stroke={chartColors.axisStroke} fontSize={10} />
                  <YAxis type="category" dataKey="ip" stroke={chartColors.axisStroke} fontSize={10} tickLine={false} width={90} />
                  <RechartsTooltip
                    contentStyle={{ 
                      backgroundColor: chartColors.tooltipBg, 
                      borderColor: chartColors.tooltipBorder, 
                      color: chartColors.tooltipText,
                      borderRadius: '8px', 
                      fontSize: '12px' 
                    }}
                  />
                  <Bar dataKey="count" fill="#06B6D4" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
          <div className="text-[11px] font-mono text-slate-500 text-center pt-2 border-t border-gray-800">
            Source IP frequency in triggered detections
          </div>
        </div>

        {/* Activity Volume Timeline Area Chart */}
        <div className="p-5 rounded-xl soc-glass border border-gray-800 space-y-3 flex flex-col">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Telemetry Frequency</h3>
            <span className="text-[10px] font-mono text-cyan-400">Chronological</span>
          </div>

          <div className="h-56 w-full flex-1 flex items-center justify-center">
            {timeline.length === 0 ? (
              <div className="text-xs font-mono text-slate-500 text-center">
                No timeline records recorded
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeline} margin={{ left: 0, right: 10, top: 10, bottom: 10 }}>
                  <defs>
                    <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#8B5CF6" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="#8B5CF6" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke={chartColors.axisStroke} fontSize={10} />
                  <YAxis stroke={chartColors.axisStroke} fontSize={10} />
                  <RechartsTooltip
                    contentStyle={{ 
                      backgroundColor: chartColors.tooltipBg, 
                      borderColor: chartColors.tooltipBorder, 
                      color: chartColors.tooltipText,
                      borderRadius: '8px', 
                      fontSize: '12px' 
                    }}
                  />
                  <Area type="monotone" dataKey="severity" stroke="#8B5CF6" fillOpacity={1} fill="url(#colorAlerts)" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
          <div className="text-[11px] font-mono text-slate-500 text-center pt-2 border-t border-gray-800">
            Live alert stream timeline
          </div>
        </div>

      </div>

      {/* Recent Alerts Triage Table */}
      <div className="p-5 rounded-xl soc-glass border border-gray-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">Recent Security Alerts</h3>
            <p className="text-xs text-slate-400">Latest detection rule matches in PostgreSQL</p>
          </div>
          <Link
            to="/alerts"
            className="inline-flex items-center space-x-1 text-xs text-cyan-400 hover:text-cyan-300 font-mono transition"
          >
            <span>View All Alerts</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </Link>
        </div>

        {recentAlerts.length === 0 ? (
          <EmptyState 
            title="No alerts logged" 
            description="The system has not logged any suspicious activity alerts yet." 
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="border-b border-gray-800 text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Alert Title</th>
                  <th className="py-2.5 px-3">Source IP</th>
                  <th className="py-2.5 px-3">Destination</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60 text-slate-300">
                {recentAlerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-gray-800/40 transition">
                    <td className="py-3 px-3 text-slate-400">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-3 font-medium text-white">
                      {alert.title}
                    </td>
                    <td className="py-3 px-3 text-cyan-400">
                      {alert.source_ip || 'N/A'}
                    </td>
                    <td className="py-3 px-3 text-slate-400">
                      {alert.destination_ip || 'N/A'}
                    </td>
                    <td className="py-3 px-3">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="py-3 px-3">
                      <StatusBadge status={alert.status} />
                    </td>
                    <td className="py-3 px-3 text-right">
                      <Link
                        to={`/alerts/${alert.id}`}
                        className="px-2.5 py-1 rounded bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 transition text-[11px]"
                      >
                        Investigate
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
}
