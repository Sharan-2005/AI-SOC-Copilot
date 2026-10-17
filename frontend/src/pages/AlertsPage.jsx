import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  AlertTriangle, 
  Search, 
  Filter, 
  ChevronLeft, 
  ChevronRight, 
  ExternalLink,
  ShieldAlert,
  RefreshCw
} from 'lucide-react';
import { fetchAlerts, updateAlert } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';
import EmptyState from '../components/EmptyState';
import { useSocRefresh } from '../context/SocRefreshContext';

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [limit] = useState(15);
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [sourceIpInput, setSourceIpInput] = useState('');
  const [appliedIp, setAppliedIp] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [patchingId, setPatchingId] = useState(null);

  const loadAlerts = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = {
        page,
        limit,
        ...(severityFilter ? { severity: severityFilter } : {}),
        ...(statusFilter ? { status: statusFilter } : {}),
        ...(appliedIp ? { source_ip: appliedIp } : {})
      };
      const res = await fetchAlerts(params);
      setAlerts(res.items || []);
      setTotal(res.total || 0);
    } catch (err) {
      setError(err.message || 'Failed to fetch alerts from backend');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [page, severityFilter, statusFilter, appliedIp]);

  useSocRefresh(loadAlerts);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    setAppliedIp(sourceIpInput.trim());
  };

  const handleStatusChange = async (alertId, newStatus) => {
    setPatchingId(alertId);
    try {
      await updateAlert(alertId, { status: newStatus });
      setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: newStatus } : a));
    } catch (err) {
      alert(`Failed to update alert: ${err.message}`);
    } finally {
      setPatchingId(null);
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            Security Alerts Management
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Rule-based threat detections stored in PostgreSQL. Total: {total}
          </p>
        </div>

        <button
          onClick={loadAlerts}
          className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-cyan-400 text-xs font-mono transition self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl soc-glass border border-gray-800 flex flex-col md:flex-row gap-4 justify-between items-stretch md:items-center">
        
        {/* IP Search */}
        <form onSubmit={handleSearchSubmit} className="relative flex-1 max-w-md">
          <input
            type="text"
            placeholder="Filter by Source IP (e.g. 198.51.100.45)..."
            value={sourceIpInput}
            onChange={(e) => setSourceIpInput(e.target.value)}
            className="w-full bg-black/50 border border-gray-700/80 rounded-lg pl-9 pr-20 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
          />
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <button
            type="submit"
            className="absolute right-1.5 top-1.5 px-2.5 py-1 rounded bg-cyan-600/30 hover:bg-cyan-600/50 text-cyan-300 text-[11px] font-mono transition"
          >
            Filter
          </button>
        </form>

        {/* Dropdown Filters */}
        <div className="flex items-center gap-3">
          
          {/* Severity filter */}
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono text-slate-400">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
              className="bg-black/50 border border-gray-700/80 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">ALL</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          {/* Status filter */}
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono text-slate-400">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
              className="bg-black/50 border border-gray-700/80 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">ALL</option>
              <option value="OPEN">OPEN</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
            </select>
          </div>

        </div>

      </div>

      {/* Main Table */}
      <div className="rounded-xl soc-glass border border-gray-800 overflow-hidden">
        {loading ? (
          <LoadingSpinner message="Querying alerts from PostgreSQL..." />
        ) : error ? (
          <ErrorMessage message={error} onRetry={loadAlerts} />
        ) : alerts.length === 0 ? (
          <EmptyState
            title="No alerts match query"
            description="Adjust your search filters or generate security events."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="border-b border-gray-800 bg-gray-900/50 text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="py-3 px-4">ID</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Alert Title</th>
                  <th className="py-3 px-4">Rule ID</th>
                  <th className="py-3 px-4">Source IP</th>
                  <th className="py-3 px-4">Destination</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Status & Triage</th>
                  <th className="py-3 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60 text-slate-300">
                {alerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-gray-800/30 transition">
                    <td className="py-3 px-4 text-slate-500">#{alert.id}</td>
                    <td className="py-3 px-4 text-slate-400">
                      {new Date(alert.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 font-medium text-white max-w-xs truncate">
                      {alert.title}
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {alert.detection_rule}
                    </td>
                    <td className="py-3 px-4 text-cyan-400">
                      {alert.source_ip || 'N/A'}
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {alert.destination_ip || 'N/A'}
                    </td>
                    <td className="py-3 px-4">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="py-3 px-4">
                      <select
                        value={alert.status}
                        disabled={patchingId === alert.id}
                        onChange={(e) => handleStatusChange(alert.id, e.target.value)}
                        className="bg-black/60 border border-gray-700 rounded px-2 py-1 text-[11px] font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
                      >
                        <option value="OPEN">OPEN</option>
                        <option value="INVESTIGATING">INVESTIGATING</option>
                        <option value="RESOLVED">RESOLVED</option>
                        <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                      </select>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <Link
                        to={`/alerts/${alert.id}`}
                        className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 transition text-[11px]"
                      >
                        <span>Inspect</span>
                        <ExternalLink className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Controls */}
        <div className="p-4 border-t border-gray-800 bg-gray-900/30 flex items-center justify-between text-xs font-mono">
          <span className="text-slate-400">
            Page {page} of {totalPages} ({total} total alerts)
          </span>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page <= 1 || loading}
              className="p-1.5 rounded bg-gray-800 hover:bg-gray-700 text-slate-300 disabled:opacity-40 transition"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages || loading}
              className="p-1.5 rounded bg-gray-800 hover:bg-gray-700 text-slate-300 disabled:opacity-40 transition"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>

      </div>

    </div>
  );
}
