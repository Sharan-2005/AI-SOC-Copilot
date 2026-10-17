import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowLeft,
  ShieldAlert,
  Activity,
  Clock,
  Globe,
  FileText,
  Layers,
  CheckCircle2,
  Sparkles
} from 'lucide-react';
import { fetchAlertById, fetchEventById, updateAlert, createIncident } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';
import { useSocRefresh } from '../context/SocRefreshContext';

export default function AlertDetailsPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [alert, setAlert] = useState(null);
  const [event, setEvent] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [creatingIncident, setCreatingIncident] = useState(false);

  const loadDetails = async () => {
    setLoading(true);
    setError(null);
    try {
      const alertData = await fetchAlertById(id);
      setAlert(alertData);
      if (alertData.event_id) {
        try {
          const eventData = await fetchEventById(alertData.event_id);
          setEvent(eventData);
        } catch {
          // Event might not exist or be null
        }
      }
    } catch (err) {
      setError(err.message || 'Failed to load alert details');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDetails();
  }, [id]);

  useSocRefresh(() => {
    navigate('/alerts');
  });

  const handleStatusChange = async (newStatus) => {
    try {
      const updated = await updateAlert(id, { status: newStatus });
      setAlert(updated);
    } catch (err) {
      window.alert(`Failed to update status: ${err.message}`);
    }
  };

  const handleCreateIncident = async () => {
    if (!window.confirm(`Create correlated Incident from Alert #${alert.id}?`)) return;
    setCreatingIncident(true);
    try {
      const incident = await createIncident({
        title: `Incident: ${alert.title}`,
        description: alert.description || `Correlated incident originated from alert #${alert.id}`,
        severity: alert.severity,
        status: 'OPEN',
        summary: `Created by analyst from detection rule ${alert.detection_rule}`,
        confidence: 0.85,
        alert_ids: [alert.id]
      });
      navigate(`/incidents/${incident.id}`);
    } catch (err) {
      window.alert(`Failed to create incident: ${err.message}`);
      setCreatingIncident(false);
    }
  };

  if (loading) return <LoadingSpinner message={`Loading alert #${id} from database...`} />;
  if (error || !alert) return <ErrorMessage message={error || 'Alert not found'} onRetry={loadDetails} />;

  return (
    <div className="space-y-6 max-w-6xl mx-auto">

      {/* Top Back & Actions Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <Link
          to="/alerts"
          className="inline-flex items-center space-x-2 text-xs font-mono text-slate-400 hover:text-cyan-400 transition"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Alerts List</span>
        </Link>

        <div className="flex items-center space-x-3">
          <select
            value={alert.status}
            onChange={(e) => handleStatusChange(e.target.value)}
            className="bg-black/60 border border-gray-700 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="OPEN">Status: OPEN</option>
            <option value="INVESTIGATING">Status: INVESTIGATING</option>
            <option value="RESOLVED">Status: RESOLVED</option>
            <option value="FALSE_POSITIVE">Status: FALSE POSITIVE</option>
          </select>

          <button
            onClick={handleCreateIncident}
            disabled={creatingIncident}
            className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-lg bg-purple-600/30 hover:bg-purple-600/40 border border-purple-500/40 text-purple-300 text-xs font-mono font-medium transition disabled:opacity-50"
          >
            <Layers className="w-4 h-4" />
            <span>{creatingIncident ? 'Creating Incident...' : 'Promote to Incident'}</span>
          </button>
        </div>
      </div>

      {/* Main Alert Metadata Card */}
      <div className="p-6 rounded-xl soc-glass border border-gray-800 space-y-6">

        {/* Title & Severity Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-gray-800 pb-5">
          <div className="space-y-1">
            <div className="flex items-center space-x-3">
              <span className="text-xs font-mono text-slate-500">ALERT #{alert.id}</span>
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
            </div>
            <h2 className="text-xl font-bold text-white mt-1">{alert.title}</h2>
          </div>

          <div className="text-right text-xs font-mono text-slate-400">
            <div className="flex items-center sm:justify-end gap-1.5">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>{new Date(alert.timestamp).toLocaleString()}</span>
            </div>
          </div>
        </div>

        {/* 4 Column Detail Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3.5 rounded-lg bg-black/40 border border-gray-800">
            <span className="text-slate-500 block">Detection Rule</span>
            <span className="text-cyan-400 font-semibold mt-1 block">{alert.detection_rule}</span>
          </div>

          <div className="p-3.5 rounded-lg bg-black/40 border border-gray-800">
            <span className="text-slate-500 block">Source IP (Attacker)</span>
            <span className="text-white font-semibold mt-1 block">{alert.source_ip || 'N/A'}</span>
          </div>

          <div className="p-3.5 rounded-lg bg-black/40 border border-gray-800">
            <span className="text-slate-500 block">Destination IP (Target)</span>
            <span className="text-white font-semibold mt-1 block">{alert.destination_ip || 'N/A'}</span>
          </div>

          <div className="p-3.5 rounded-lg bg-black/40 border border-gray-800">
            <span className="text-slate-500 block">Triggering Event ID</span>
            <span className="text-purple-400 font-semibold mt-1 block">
              {alert.event_id ? `#${alert.event_id}` : 'Direct Trigger'}
            </span>
          </div>
        </div>

        {/* Description */}
        <div className="space-y-1.5">
          <h4 className="text-xs font-mono uppercase text-slate-400 tracking-wider">Detection Description</h4>
          <p className="text-xs text-slate-300 font-mono bg-black/30 p-3 rounded-lg border border-gray-800 leading-relaxed">
            {alert.description || 'No description logged with this detection rule.'}
          </p>
        </div>

      </div>

      {/* AI Copilot Investigation (Phase 5 Placeholder Card) */}
      <div className="p-6 rounded-xl soc-glass border border-cyan-500/20 bg-cyan-950/10 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white">Google Gemini AI Investigation</h3>
              <p className="text-xs text-slate-400">Automated reasoning, evidence correlation, and MITRE mapping</p>
            </div>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
            PHASE 5 ENGINE
          </span>
        </div>

        <div className="p-4 rounded-lg bg-black/50 border border-gray-800 text-xs font-mono text-slate-400 space-y-2">
          <p>
            The Gemini AI alert analyzer will be activated in Phase 5. It will synthesize the triggering events, assign calibrated confidence, and recommend non-destructive containment actions.
          </p>
          <div className="pt-2 flex items-center gap-3">
            <button
              disabled
              className="px-3 py-1.5 rounded bg-gray-800 text-slate-500 border border-gray-700 cursor-not-allowed text-xs font-mono"
            >
              Analyze with Gemini (Phase 5)
            </button>
            <span className="text-[11px] text-slate-500">Awaiting Phase 5 activation</span>
          </div>
        </div>
      </div>

      {/* Associated Event Telemetry */}
      {event && (
        <div className="p-6 rounded-xl soc-glass border border-gray-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">Triggering Telemetry Event #{event.id}</h3>
            </div>
            <span className="text-xs font-mono text-slate-400">Source: {event.source}</span>
          </div>

          <div className="bg-black/60 rounded-lg p-4 border border-gray-800/80 overflow-x-auto">
            <pre className="text-xs font-mono text-cyan-300 leading-relaxed">
              {JSON.stringify(event.raw_data || event, null, 2)}
            </pre>
          </div>
        </div>
      )}

    </div>
  );
}
