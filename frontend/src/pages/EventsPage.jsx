import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  Activity, 
  Search, 
  ChevronLeft, 
  ChevronRight, 
  Code2, 
  X, 
  RefreshCw, 
  Terminal,
  UploadCloud
} from 'lucide-react';
import { fetchEvents } from '../services/api';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';
import EmptyState from '../components/EmptyState';
import { useSocRefresh } from '../context/SocRefreshContext';

export default function EventsPage() {
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [limit] = useState(20);
  const [eventTypeFilter, setEventTypeFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [sourceIpInput, setSourceIpInput] = useState('');
  const [appliedIp, setAppliedIp] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Raw JSON Inspection Modal
  const [selectedEvent, setSelectedEvent] = useState(null);

  const loadEvents = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = {
        page,
        limit,
        ...(eventTypeFilter ? { event_type: eventTypeFilter } : {}),
        ...(sourceFilter ? { source: sourceFilter } : {}),
        ...(appliedIp ? { source_ip: appliedIp } : {})
      };
      const res = await fetchEvents(params);
      setEvents(res.items || []);
      setTotal(res.total || 0);
    } catch (err) {
      setError(err.message || 'Failed to query security events');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, [page, eventTypeFilter, sourceFilter, appliedIp]);

  useSocRefresh(loadEvents);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    setAppliedIp(sourceIpInput.trim());
  };

  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            Security Event Stream
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Ingested and normalized security telemetry in PostgreSQL. Total: {total}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/upload"
            className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/30 text-cyan-400 text-xs font-mono transition"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            <span>Upload Logs</span>
          </Link>
          <button
            onClick={loadEvents}
            className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-cyan-400 text-xs font-mono transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="p-4 rounded-xl soc-glass border border-gray-800 flex flex-col md:flex-row gap-4 justify-between items-stretch md:items-center">
        <form onSubmit={handleSearchSubmit} className="relative flex-1 max-w-md">
          <input
            type="text"
            placeholder="Search by Source IP..."
            value={sourceIpInput}
            onChange={(e) => setSourceIpInput(e.target.value)}
            className="w-full bg-black/50 border border-gray-700 rounded-lg pl-9 pr-20 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <button
            type="submit"
            className="absolute right-1.5 top-1.5 px-2.5 py-1 rounded bg-cyan-600/30 hover:bg-cyan-600/50 text-cyan-300 text-[11px] font-mono"
          >
            Filter
          </button>
        </form>

        <div className="flex items-center gap-3">
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-slate-400">Event Type:</span>
            <select
              value={eventTypeFilter}
              onChange={(e) => { setEventTypeFilter(e.target.value); setPage(1); }}
              className="bg-black/50 border border-gray-700 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">ALL</option>
              <option value="failed_login">failed_login</option>
              <option value="successful_login">successful_login</option>
              <option value="port_scan">port_scan</option>
              <option value="network_flow">network_flow</option>
              <option value="command_exec">command_exec</option>
            </select>
          </div>

          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-slate-400">Source:</span>
            <select
              value={sourceFilter}
              onChange={(e) => { setSourceFilter(e.target.value); setPage(1); }}
              className="bg-black/50 border border-gray-700 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">ALL</option>
              <option value="auth_log">auth_log</option>
              <option value="suricata">suricata</option>
              <option value="wazuh">wazuh</option>
              <option value="zeek">zeek</option>
              <option value="simulator">simulator</option>
            </select>
          </div>
        </div>
      </div>

      {/* Events Table */}
      <div className="rounded-xl soc-glass border border-gray-800 overflow-hidden">
        {loading ? (
          <LoadingSpinner message="Querying events..." />
        ) : error ? (
          <ErrorMessage message={error} onRetry={loadEvents} />
        ) : events.length === 0 ? (
          <EmptyState
            title="No events found"
            description="No events match your current filter criteria."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="border-b border-gray-800 bg-gray-900/50 text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="py-3 px-4">ID</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Source</th>
                  <th className="py-3 px-4">Event Type</th>
                  <th className="py-3 px-4">Host</th>
                  <th className="py-3 px-4">Source IP</th>
                  <th className="py-3 px-4">Destination IP</th>
                  <th className="py-3 px-4">Proto / Port</th>
                  <th className="py-3 px-4 text-right">Payload</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60 text-slate-300">
                {events.map((ev) => (
                  <tr key={ev.id} className="hover:bg-gray-800/30 transition">
                    <td className="py-3 px-4 text-slate-500">#{ev.id}</td>
                    <td className="py-3 px-4 text-slate-400">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-4 text-purple-400">{ev.source}</td>
                    <td className="py-3 px-4 font-semibold text-white">
                      <span className="px-2 py-0.5 rounded bg-gray-800 border border-gray-700">
                        {ev.event_type}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400">{ev.host || 'N/A'}</td>
                    <td className="py-3 px-4 text-cyan-400">{ev.source_ip || 'N/A'}</td>
                    <td className="py-3 px-4 text-slate-300">{ev.destination_ip || 'N/A'}</td>
                    <td className="py-3 px-4 text-slate-400">
                      {ev.protocol || 'TCP'}:{ev.destination_port || 'N/A'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setSelectedEvent(ev)}
                        className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-gray-800 hover:bg-gray-700 text-slate-300 transition text-[11px]"
                      >
                        <Code2 className="w-3 h-3 text-cyan-400" />
                        <span>JSON</span>
                      </button>
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

      {/* Raw JSON Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm" onClick={() => setSelectedEvent(null)} />
          <div className="relative w-full max-w-2xl bg-[#111827] border border-gray-800 rounded-xl p-6 shadow-2xl z-10 space-y-4">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <div className="flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-white font-mono">
                  Normalized Event Payload #{selectedEvent.id}
                </h3>
              </div>
              <button onClick={() => setSelectedEvent(null)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="bg-black/60 rounded-lg p-4 border border-gray-800 max-h-96 overflow-y-auto">
              <pre className="text-xs font-mono text-cyan-300 leading-relaxed">
                {JSON.stringify(selectedEvent, null, 2)}
              </pre>
            </div>

            <div className="flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-1.5 rounded-lg bg-gray-800 text-slate-300 hover:text-white text-xs font-mono transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
