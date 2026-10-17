import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  ShieldAlert, 
  Layers, 
  Plus, 
  Clock, 
  ChevronLeft, 
  ChevronRight, 
  ExternalLink,
  RefreshCw,
  X
} from 'lucide-react';
import { fetchIncidents, createIncident } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';
import EmptyState from '../components/EmptyState';
import { useSocRefresh } from '../context/SocRefreshContext';

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [limit] = useState(10);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Create Incident Modal State
  const [modalOpen, setModalOpen] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newSeverity, setNewSeverity] = useState('HIGH');
  const [submitting, setSubmitting] = useState(false);

  const loadIncidents = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = {
        page,
        limit,
        ...(statusFilter ? { status: statusFilter } : {}),
        ...(severityFilter ? { severity: severityFilter } : {})
      };
      const res = await fetchIncidents(params);
      setIncidents(res.items || []);
      setTotal(res.total || 0);
    } catch (err) {
      setError(err.message || 'Failed to load incidents');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, [page, statusFilter, severityFilter]);

  useSocRefresh(loadIncidents);

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    setSubmitting(true);
    try {
      await createIncident({
        title: newTitle.trim(),
        description: newDesc.trim() || 'Manual incident created by analyst.',
        severity: newSeverity,
        status: 'OPEN',
        confidence: 0.90,
        alert_ids: []
      });
      setModalOpen(false);
      setNewTitle('');
      setNewDesc('');
      loadIncidents();
    } catch (err) {
      window.alert(`Failed to create incident: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <div className="space-y-6">
      
      {/* Top Header & New Incident Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-purple-400" />
            Security Incidents Management
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Correlated multi-alert attack investigations. Total: {total}
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => setModalOpen(true)}
            className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-mono font-medium transition"
          >
            <Plus className="w-4 h-4" />
            <span>Create Incident</span>
          </button>

          <button
            onClick={loadIncidents}
            className="p-2 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-cyan-400 text-xs transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl soc-glass border border-gray-800 flex items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-slate-400">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
              className="bg-black/50 border border-gray-700/80 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">ALL</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-slate-400">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
              className="bg-black/50 border border-gray-700/80 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">ALL</option>
              <option value="OPEN">OPEN</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="CONTAINED">CONTAINED</option>
              <option value="RESOLVED">RESOLVED</option>
            </select>
          </div>
        </div>

        <span className="text-xs font-mono text-slate-500">
          Showing {incidents.length} of {total} incidents
        </span>
      </div>

      {/* Incidents Table */}
      <div className="rounded-xl soc-glass border border-gray-800 overflow-hidden">
        {loading ? (
          <LoadingSpinner message="Querying incidents from PostgreSQL..." />
        ) : error ? (
          <ErrorMessage message={error} onRetry={loadIncidents} />
        ) : incidents.length === 0 ? (
          <EmptyState
            title="No incidents registered"
            description="Create an incident or promote an alert to start an investigation."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="border-b border-gray-800 bg-gray-900/50 text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="py-3 px-4">ID</th>
                  <th className="py-3 px-4">Incident Title</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Correlated Alerts</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Created At</th>
                  <th className="py-3 px-4 text-right">Investigation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60 text-slate-300">
                {incidents.map((incident) => (
                  <tr key={incident.id} className="hover:bg-gray-800/30 transition">
                    <td className="py-3 px-4 text-purple-400">#{incident.id}</td>
                    <td className="py-3 px-4 font-semibold text-white max-w-sm truncate">
                      {incident.title}
                    </td>
                    <td className="py-3 px-4">
                      <SeverityBadge severity={incident.severity} />
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge status={incident.status} />
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-gray-800 text-slate-300 border border-gray-700">
                        {incident.alert_ids?.length || 0} alerts
                      </span>
                    </td>
                    <td className="py-3 px-4 text-cyan-400">
                      {incident.confidence != null ? `${Math.round(incident.confidence * 100)}%` : 'N/A'}
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {new Date(incident.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <Link
                        to={`/incidents/${incident.id}`}
                        className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 border border-purple-500/30 transition text-[11px]"
                      >
                        <span>Investigate</span>
                        <ExternalLink className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        <div className="p-4 border-t border-gray-800 bg-gray-900/30 flex items-center justify-between text-xs font-mono">
          <span className="text-slate-400">
            Page {page} of {totalPages}
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

      {/* Create Incident Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm" onClick={() => setModalOpen(false)} />
          <div className="relative w-full max-w-lg bg-[#111827] border border-gray-800 rounded-xl p-6 shadow-2xl z-10 space-y-4">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-purple-400" />
                Initialize New Security Incident
              </h3>
              <button onClick={() => setModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateSubmit} className="space-y-4 text-xs font-mono">
              <div className="space-y-1">
                <label className="text-slate-300">Incident Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Distributed SSH Brute Force & Ingress Anomaly"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full bg-black/50 border border-gray-700 rounded-lg p-2.5 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-slate-300">Severity</label>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value)}
                  className="w-full bg-black/50 border border-gray-700 rounded-lg p-2.5 text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-slate-300">Description & Context</label>
                <textarea
                  rows={3}
                  placeholder="Summarize initial findings or attack indicators..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full bg-black/50 border border-gray-700 rounded-lg p-2.5 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="pt-3 flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-gray-800 text-slate-400 hover:text-white transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold transition disabled:opacity-50"
                >
                  {submitting ? 'Creating...' : 'Create Incident'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
}
