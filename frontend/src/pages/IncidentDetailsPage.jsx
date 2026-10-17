import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { 
  ShieldAlert, 
  ArrowLeft, 
  Clock, 
  Layers, 
  AlertTriangle, 
  Sparkles, 
  ExternalLink,
  CheckCircle2,
  Calendar,
  Activity
} from 'lucide-react';
import { fetchIncidentById, fetchAlertById, updateIncident } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';
import { useSocRefresh } from '../context/SocRefreshContext';

export default function IncidentDetailsPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [incident, setIncident] = useState(null);
  const [correlatedAlerts, setCorrelatedAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [statusUpdating, setStatusUpdating] = useState(false);

  const loadIncident = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchIncidentById(id);
      setIncident(data);
      // Fetch associated alerts
      if (data.alert_ids && data.alert_ids.length > 0) {
        const alertPromises = data.alert_ids.map(aId => fetchAlertById(aId).catch(() => null));
        const alerts = await Promise.all(alertPromises);
        // Sort chronologically
        const validAlerts = alerts
          .filter(Boolean)
          .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        setCorrelatedAlerts(validAlerts);
      } else {
        setCorrelatedAlerts([]);
      }
    } catch (err) {
      setError(err.message || 'Failed to load incident details');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncident();
  }, [id]);

  useSocRefresh(() => {
    navigate('/incidents');
  });

  const handleStatusChange = async (newStatus) => {
    setStatusUpdating(true);
    try {
      const updated = await updateIncident(id, { status: newStatus });
      setIncident(prev => ({ ...prev, status: updated.status }));
    } catch (err) {
      window.alert(`Failed to update incident: ${err.message}`);
    } finally {
      setStatusUpdating(false);
    }
  };

  if (loading) return <LoadingSpinner message={`Loading incident #${id} investigation...`} />;
  if (error || !incident) return <ErrorMessage message={error || 'Incident not found'} onRetry={loadIncident} />;

  // Distinct source IPs and hosts from correlated alerts
  const uniqueSourceIps = Array.from(new Set(correlatedAlerts.map(a => a.source_ip).filter(Boolean)));
  const uniqueDestIps = Array.from(new Set(correlatedAlerts.map(a => a.destination_ip).filter(Boolean)));

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      
      {/* Top Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <Link
          to="/incidents"
          className="inline-flex items-center space-x-2 text-xs font-mono text-slate-400 hover:text-cyan-400 transition"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Incidents List</span>
        </Link>

        <div className="flex items-center space-x-3">
          <span className="text-xs font-mono text-slate-400">Status:</span>
          <select
            value={incident.status}
            disabled={statusUpdating}
            onChange={(e) => handleStatusChange(e.target.value)}
            className="bg-black/60 border border-gray-700 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="OPEN">OPEN</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="CONTAINED">CONTAINED</option>
            <option value="RESOLVED">RESOLVED</option>
          </select>
        </div>
      </div>

      {/* Incident Overview Card */}
      <div className="p-6 rounded-xl soc-glass border border-gray-800 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-gray-800 pb-5">
          <div className="space-y-1">
            <div className="flex items-center space-x-3">
              <span className="text-xs font-mono text-purple-400 font-semibold">INCIDENT #{incident.id}</span>
              <SeverityBadge severity={incident.severity} />
              <StatusBadge status={incident.status} />
            </div>
            <h2 className="text-xl font-bold text-white mt-1">{incident.title}</h2>
          </div>

          <div className="text-right text-xs font-mono text-slate-400">
            <div className="flex items-center sm:justify-end gap-1.5">
              <Calendar className="w-3.5 h-3.5 text-cyan-400" />
              <span>Created: {new Date(incident.created_at).toLocaleString()}</span>
            </div>
          </div>
        </div>

        {/* 4 Summary Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3.5 rounded-lg bg-black/40 border border-gray-800">
            <span className="text-slate-500 block">Correlated Alerts</span>
            <span className="text-cyan-400 font-semibold mt-1 block">
              {correlatedAlerts.length} Alerts
            </span>
          </div>

          <div className="p-3.5 rounded-lg bg-black/40 border border-gray-800">
            <span className="text-slate-500 block">Threat Indicators (Source IPs)</span>
            <span className="text-white font-semibold mt-1 block">
              {uniqueSourceIps.length > 0 ? uniqueSourceIps.join(', ') : 'N/A'}
            </span>
          </div>

          <div className="p-3.5 rounded-lg bg-black/40 border border-gray-800">
            <span className="text-slate-500 block">Target Assets (Dest IPs)</span>
            <span className="text-white font-semibold mt-1 block">
              {uniqueDestIps.length > 0 ? uniqueDestIps.join(', ') : 'Internal Subnet'}
            </span>
          </div>

          <div className="p-3.5 rounded-lg bg-black/40 border border-gray-800">
            <span className="text-slate-500 block">Correlation Confidence</span>
            <span className="text-purple-400 font-semibold mt-1 block">
              {incident.confidence != null ? `${Math.round(incident.confidence * 100)}%` : '85%'}
            </span>
          </div>
        </div>

        {/* Summary */}
        <div className="space-y-1.5">
          <h4 className="text-xs font-mono uppercase text-slate-400 tracking-wider">Incident Summary</h4>
          <p className="text-xs text-slate-300 font-mono bg-black/30 p-3.5 rounded-lg border border-gray-800 leading-relaxed">
            {incident.summary || incident.description || 'No incident narrative recorded.'}
          </p>
        </div>
      </div>

      {/* AI Copilot Incident Synthesizer (Phase 5/6 Placeholder Card) */}
      <div className="p-6 rounded-xl soc-glass border border-purple-500/20 bg-purple-950/10 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-400">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white">AI Incident Narrative & Kill Chain Analysis</h3>
              <p className="text-xs text-slate-400">Synthesize multi-stage events into an executive briefing</p>
            </div>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-400 border border-purple-800">
            PHASE 5 ENGINE
          </span>
        </div>

        <div className="p-4 rounded-lg bg-black/50 border border-gray-800 text-xs font-mono text-slate-400 space-y-2">
          <p>
            In Phase 5, the Google Gemini engine will automatically reconstruct the attack progression across the MITRE ATT&CK kill chain and generate human-in-the-loop response actions.
          </p>
          <div className="pt-2 flex items-center gap-3">
            <button
              disabled
              className="px-3.5 py-1.5 rounded bg-gray-800 text-slate-500 border border-gray-700 cursor-not-allowed text-xs font-mono"
            >
              Generate AI Incident Summary (Phase 5)
            </button>
            <span className="text-[11px] text-slate-500">Awaiting Phase 5 activation</span>
          </div>
        </div>
      </div>

      {/* Chronological Correlated Alert Timeline */}
      <div className="p-6 rounded-xl soc-glass border border-gray-800 space-y-6">
        <div className="flex items-center justify-between border-b border-gray-800 pb-4">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Correlated Attack Timeline ({correlatedAlerts.length} Events)
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Chronological progression of detected alerts linked to this incident.
            </p>
          </div>
        </div>

        {correlatedAlerts.length === 0 ? (
          <div className="p-6 text-center text-xs font-mono text-slate-500">
            No alerts linked to this incident yet. Promote alerts from the Alerts tab.
          </div>
        ) : (
          <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-gray-800">
            {correlatedAlerts.map((alert, idx) => (
              <div key={alert.id} className="relative group">
                
                {/* Timeline node icon */}
                <div className="absolute -left-6 top-1 w-3 h-3 rounded-full bg-cyan-400 ring-4 ring-gray-900 group-hover:scale-125 transition" />

                {/* Timeline card */}
                <div className="p-4 rounded-lg bg-black/40 border border-gray-800 hover:border-gray-700 transition space-y-2">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-mono text-slate-500">Step {idx + 1}</span>
                      <h4 className="text-xs font-bold text-white">{alert.title}</h4>
                      <SeverityBadge severity={alert.severity} />
                    </div>
                    <span className="text-[11px] font-mono text-slate-400">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <p className="text-xs font-mono text-slate-400 leading-relaxed">
                    {alert.description || 'Detection rule triggered.'}
                  </p>

                  <div className="flex items-center justify-between pt-2 border-t border-gray-800/80 text-[11px] font-mono">
                    <div className="flex items-center space-x-3 text-slate-400">
                      <span>Source: <span className="text-cyan-400">{alert.source_ip || 'N/A'}</span></span>
                      <span>Target: <span className="text-slate-300">{alert.destination_ip || 'N/A'}</span></span>
                      <span>Rule: <span className="text-purple-400">{alert.detection_rule}</span></span>
                    </div>

                    <Link
                      to={`/alerts/${alert.id}`}
                      className="inline-flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 transition"
                    >
                      <span>Inspect Alert</span>
                      <ExternalLink className="w-3 h-3" />
                    </Link>
                  </div>
                </div>

              </div>
            ))}
          </div>
        )}

      </div>

    </div>
  );
}
