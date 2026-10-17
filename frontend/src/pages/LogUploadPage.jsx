import React, { useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import { 
  UploadCloud, 
  FileText, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldAlert, 
  ArrowRight, 
  RefreshCw, 
  FileCheck, 
  Info,
  Layers
} from 'lucide-react';
import { uploadLogFile } from '../services/api';
import { useSocRefresh } from '../context/SocRefreshContext';

const SAMPLE_LOGS = {
  auth_log: `Sep 17 14:10:01 auth-srv sshd[101]: Failed password for invalid user admin from 198.51.100.45 port 51201 ssh2
Sep 17 14:10:03 auth-srv sshd[102]: Failed password for invalid user root from 198.51.100.45 port 51202 ssh2
Sep 17 14:10:05 auth-srv sshd[103]: Failed password for invalid user deploy from 198.51.100.45 port 51203 ssh2
Sep 17 14:10:07 auth-srv sshd[104]: Failed password for invalid user ubuntu from 198.51.100.45 port 51204 ssh2
Sep 17 14:10:09 auth-srv sshd[105]: Failed password for invalid user oracle from 198.51.100.45 port 51205 ssh2
Sep 17 14:10:11 auth-srv sshd[106]: Failed password for invalid user test from 198.51.100.45 port 51206 ssh2
Sep 17 14:10:13 auth-srv sshd[107]: Failed password for invalid user backup from 198.51.100.45 port 51207 ssh2
Sep 17 14:10:15 auth-srv sshd[108]: Failed password for invalid user service from 198.51.100.45 port 51208 ssh2
Sep 17 14:10:17 auth-srv sshd[109]: Failed password for invalid user guest from 198.51.100.45 port 51209 ssh2
Sep 17 14:10:19 auth-srv sshd[110]: Failed password for invalid user operator from 198.51.100.45 port 51210 ssh2
Sep 17 14:10:21 auth-srv sshd[111]: Failed password for invalid user sysadmin from 198.51.100.45 port 51211 ssh2
Sep 17 14:10:25 auth-srv sshd[112]: Accepted password for analyst from 10.0.0.22 port 48900 ssh2`,

  web_attack: `198.51.100.77 - - [17/Sep/2026:14:15:10 +0000] "GET /index.php?id=1' UNION SELECT username, password_hash FROM users-- HTTP/1.1" 200 4520 "-" "Mozilla/5.0"
198.51.100.77 - - [17/Sep/2026:14:15:14 +0000] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 403 289 "-" "Mozilla/5.0"
198.51.100.77 - - [17/Sep/2026:14:15:18 +0000] "POST /login.php HTTP/1.1" 401 1042 "-" "Mozilla/5.0"
198.51.100.77 - - [17/Sep/2026:14:15:22 +0000] "GET /search?q=' OR 1=1-- HTTP/1.1" 200 3120 "-" "Mozilla/5.0"`,

  json_stream: `[
  {"timestamp": "2026-09-17T14:20:00Z", "source_ip": "192.168.1.99", "destination_port": 22, "event_type": "failed_login", "raw_data": {"user": "admin"}},
  {"timestamp": "2026-09-17T14:20:05Z", "source_ip": "192.168.1.99", "destination_port": 22, "event_type": "failed_login", "raw_data": {"user": "root"}},
  {"timestamp": "2026-09-17T14:20:10Z", "source_ip": "192.168.1.99", "destination_port": 80, "event_type": "http_request", "raw_data": {"path": "/admin' OR 1=1"}}
]`
};

export default function LogUploadPage() {
  const [file, setFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  useSocRefresh(() => {
    setResult(null);
    setError(null);
  });

  const ALLOWED_EXTENSIONS = ['.log', '.txt', '.json', '.csv'];

  const isAllowedFile = (fileObj) => {
    if (!fileObj || !fileObj.name) return false;
    const name = fileObj.name.toLowerCase();
    return ALLOWED_EXTENSIONS.some((ext) => name.endsWith(ext));
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const droppedFile = e.dataTransfer.files[0];
      if (!isAllowedFile(droppedFile)) {
        const ext = droppedFile.name.includes('.') ? `.${droppedFile.name.split('.').pop()}` : 'unknown';
        setError(`Unsupported file format '${ext}'. Only .log, .txt, .json, and .csv files are permitted.`);
        setFile(null);
        setResult(null);
        return;
      }
      setFile(droppedFile);
      setError(null);
      setResult(null);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      const chosenFile = e.target.files[0];
      if (!isAllowedFile(chosenFile)) {
        const ext = chosenFile.name.includes('.') ? `.${chosenFile.name.split('.').pop()}` : 'unknown';
        setError(`Unsupported file format '${ext}'. Only .log, .txt, .json, and .csv files are permitted.`);
        setFile(null);
        setResult(null);
        e.target.value = '';
        return;
      }
      setFile(chosenFile);
      setError(null);
      setResult(null);
      e.target.value = '';
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    if (!isAllowedFile(file)) {
      setError('Unsupported file format. Please upload a valid .log, .txt, .json, or .csv file.');
      return;
    }
    setUploading(true);
    setError(null);
    try {
      const data = await uploadLogFile(file);
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to upload log file');
    } finally {
      setUploading(false);
    }
  };

  const handleUseSample = (sampleKey, filename) => {
    const content = SAMPLE_LOGS[sampleKey];
    const blob = new Blob([content], { type: 'text/plain' });
    const sampleFile = new File([blob], filename, { type: 'text/plain' });
    setFile(sampleFile);
    setError(null);
    setResult(null);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      
      {/* Page Header */}
      <div className="border-b border-gray-800 pb-5">
        <h2 className="text-xl font-bold text-white flex items-center gap-2.5">
          <UploadCloud className="w-6 h-6 text-cyan-400" />
          Upload Security Logs
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Ingest raw telemetry into canonical events and execute the deterministic detection engine.
        </p>
      </div>

      {/* Supported Formats Banner */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl soc-glass border border-gray-800 text-xs font-mono">
        <div className="flex items-center gap-2 text-slate-300">
          <Info className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>Supported File Formats:</span>
        </div>
        <div className="flex items-center gap-2">
          {['.LOG (Syslog / Auth)', '.TXT', '.JSON / NDJSON', '.CSV'].map((fmt) => (
            <span
              key={fmt}
              className="px-2.5 py-1 rounded bg-black/40 border border-gray-700 text-cyan-400 text-[11px] font-semibold"
            >
              {fmt}
            </span>
          ))}
        </div>
      </div>

      {/* Main Upload Zone */}
      <div className="p-6 rounded-xl soc-glass border border-gray-800 space-y-6">
        
        <div
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition flex flex-col items-center justify-center min-h-[200px] ${
            dragActive
              ? 'border-cyan-400 bg-cyan-500/10'
              : file
              ? 'border-emerald-500/60 bg-emerald-500/5'
              : 'border-gray-700 hover:border-gray-600 bg-black/30'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".log,.txt,.json,.csv"
            onChange={handleFileChange}
            className="hidden"
          />

          {file ? (
            <div className="space-y-2">
              <div className="inline-flex p-3 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                <FileCheck className="w-8 h-8" />
              </div>
              <p className="text-sm font-bold text-white font-mono">{file.name}</p>
              <p className="text-xs text-slate-400 font-mono">
                {(file.size / 1024).toFixed(1)} KB — Ready to Ingest
              </p>
              <span className="text-[11px] text-cyan-400 underline block pt-1">
                Click or drag to choose a different file
              </span>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="inline-flex p-3 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                <UploadCloud className="w-8 h-8" />
              </div>
              <div>
                <p className="text-sm font-semibold text-white">
                  Drag and drop your security log file here, or{' '}
                  <span className="text-cyan-400 underline">browse</span>
                </p>
                <p className="text-xs text-slate-400 mt-1 font-mono">
                  Supports .log, .txt, .json, .csv files up to 10MB
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-between pt-2">
          <div className="text-xs text-slate-500 font-mono">
            {file ? `Selected: ${file.name}` : 'No file selected'}
          </div>

          <button
            onClick={handleUpload}
            disabled={!file || uploading}
            className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-xs font-mono transition shadow-lg shadow-cyan-600/20"
          >
            {uploading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Processing & Detecting...</span>
              </>
            ) : (
              <>
                <UploadCloud className="w-4 h-4" />
                <span>Upload & Ingest Logs</span>
              </>
            )}
          </button>
        </div>

        {/* Error Notification */}
        {error && (
          <div className="p-4 rounded-lg bg-red-950/40 border border-red-800 text-xs font-mono text-red-300 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Ingestion Results Card */}
        {result && (
          <div className="p-6 rounded-xl bg-[#0d1527] border border-cyan-500/30 space-y-4">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <div className="flex items-center space-x-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-bold text-white font-mono">Log Processing Summary</h3>
              </div>
              <span className="text-xs font-mono text-cyan-400 uppercase bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800">
                Format: {result.format}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs font-mono">
              <div className="p-3 bg-black/40 rounded-lg border border-gray-800">
                <span className="text-slate-500 block text-[11px]">Total Records</span>
                <span className="text-white font-bold text-base mt-0.5 block">{result.total_records}</span>
              </div>

              <div className="p-3 bg-black/40 rounded-lg border border-gray-800">
                <span className="text-slate-500 block text-[11px]">Parsed & Stored</span>
                <span className="text-emerald-400 font-bold text-base mt-0.5 block">{result.parsed_records}</span>
              </div>

              <div className="p-3 bg-black/40 rounded-lg border border-gray-800">
                <span className="text-slate-500 block text-[11px]">Failed Records</span>
                <span className={`font-bold text-base mt-0.5 block ${result.failed_records > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
                  {result.failed_records}
                </span>
              </div>

              <div className="p-3 bg-black/40 rounded-lg border border-gray-800">
                <span className="text-slate-500 block text-[11px]">Alerts Generated</span>
                <span className={`font-bold text-base mt-0.5 block ${result.alerts_created > 0 ? 'text-red-400' : 'text-cyan-400'}`}>
                  {result.alerts_created}
                </span>
              </div>

              <div className="p-3 bg-black/40 rounded-lg border border-gray-800">
                <span className="text-slate-500 block text-[11px]">Incidents Correlated</span>
                <span className={`font-bold text-base mt-0.5 block ${result.incidents_created > 0 ? 'text-purple-400' : 'text-slate-400'}`}>
                  {result.incidents_created ?? 0}
                </span>
              </div>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-gray-800/80">
              <span className="text-xs text-slate-400 font-mono">
                Events stored in Supabase PostgreSQL and evaluated against 5 deterministic detection rules.
              </span>
              <div className="flex items-center gap-3">
                <Link
                  to="/alerts"
                  className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-purple-600/30 hover:bg-purple-600/50 border border-purple-500/40 text-purple-300 text-xs font-mono font-medium transition"
                >
                  <span>View Alerts ({result.alerts_created})</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
                <Link
                  to="/events"
                  className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-slate-300 text-xs font-mono font-medium transition"
                >
                  <span>View Event Stream</span>
                </Link>
              </div>
            </div>
          </div>
        )}

      </div>

      {/* Demo Test Logs Section */}
      <div className="p-5 rounded-xl soc-glass border border-gray-800 space-y-3">
        <h4 className="text-xs font-mono uppercase text-slate-400 tracking-wider">
          Quick Demo Presets (Test Ingestion with 1 Click)
        </h4>
        <p className="text-xs text-slate-400">
          Click any preset below to load a simulated security log file for instant testing:
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1 font-mono text-xs">
          <button
            onClick={() => handleUseSample('auth_log', 'auth_brute_force.log')}
            className="p-3 rounded-lg bg-black/40 hover:bg-black/70 border border-gray-800 hover:border-cyan-500/50 text-left transition space-y-1"
          >
            <div className="flex items-center justify-between text-cyan-400 font-bold">
              <span>Linux Auth Log</span>
              <span className="text-[10px] text-slate-500">.LOG</span>
            </div>
            <p className="text-[11px] text-slate-400">11 Failed SSH attempts + 1 success. Triggers T1110 (Brute Force).</p>
          </button>

          <button
            onClick={() => handleUseSample('web_attack', 'access_attack.log')}
            className="p-3 rounded-lg bg-black/40 hover:bg-black/70 border border-gray-800 hover:border-cyan-500/50 text-left transition space-y-1"
          >
            <div className="flex items-center justify-between text-purple-400 font-bold">
              <span>Web Server Access Log</span>
              <span className="text-[10px] text-slate-500">.LOG</span>
            </div>
            <p className="text-[11px] text-slate-400">SQL injection and Path Traversal probes. Triggers T1190 (Web Attack).</p>
          </button>

          <button
            onClick={() => handleUseSample('json_stream', 'events_batch.json')}
            className="p-3 rounded-lg bg-black/40 hover:bg-black/70 border border-gray-800 hover:border-cyan-500/50 text-left transition space-y-1"
          >
            <div className="flex items-center justify-between text-emerald-400 font-bold">
              <span>JSON Event Stream</span>
              <span className="text-[10px] text-slate-500">.JSON</span>
            </div>
            <p className="text-[11px] text-slate-400">JSON array of multi-vector security events with metadata.</p>
          </button>
        </div>
      </div>

    </div>
  );
}
