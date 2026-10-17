import React, { useState, useEffect } from 'react';
import { Grid, Search, ExternalLink, ShieldAlert, RefreshCw, BookOpen, Layers, ShieldCheck, Radio, Sliders } from 'lucide-react';
import { fetchMitreTechniques, fetchDetectionRules } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';
import EmptyState from '../components/EmptyState';

export default function MitrePage() {
  const [techniques, setTechniques] = useState([]);
  const [rules, setRules] = useState([]);
  const [search, setSearch] = useState('');
  const [tacticFilter, setTacticFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [techData, rulesData] = await Promise.all([
        fetchMitreTechniques(),
        fetchDetectionRules().catch(() => [])
      ]);
      setTechniques(techData || []);
      setRules(rulesData || []);
    } catch (err) {
      setError(err.message || 'Failed to load MITRE ATT&CK techniques and rules');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const tactics = Array.from(new Set(techniques.map(t => t.tactic).filter(Boolean)));

  const filteredTechniques = techniques.filter(t => {
    const matchesSearch = 
      t.technique_id.toLowerCase().includes(search.toLowerCase()) ||
      t.name.toLowerCase().includes(search.toLowerCase()) ||
      (t.description && t.description.toLowerCase().includes(search.toLowerCase()));
    const matchesTactic = !tacticFilter || t.tactic === tacticFilter;
    return matchesSearch && matchesTactic;
  });

  return (
    <div className="space-y-8">
      
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
            <Grid className="w-5 h-5 text-cyan-400" />
            MITRE ATT&CK® Matrix &amp; Detection Rule Registry
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Adversarial tactics, techniques, and Phase 1–5 deterministic detection rules.
          </p>
        </div>

        <button
          onClick={loadData}
          className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-cyan-400 text-xs font-mono transition self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh All</span>
        </button>
      </div>

      {/* =========================================================================
          SECTION 6: ACTIVE SOC DETECTION RULES TABLE (RULE_01 to RULE_07)
          ========================================================================= */}
      <div className="p-6 rounded-xl soc-glass border border-gray-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              <Layers className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white tracking-wide">SOC Active Detection Rules Registry</h3>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Deterministic detection engines evaluated against ingested logs and live network traffic.
              </p>
            </div>
          </div>
          <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800 self-start sm:self-auto">
            7 ACTIVE RULES (PHASES 1–5)
          </span>
        </div>

        <div className="overflow-x-auto pt-2">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="border-b border-gray-800 text-slate-400 bg-gray-900/50">
                <th className="py-2.5 px-3">Rule ID</th>
                <th className="py-2.5 px-3">Rule Name &amp; Description</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Telemetry Source</th>
                <th className="py-2.5 px-3">MITRE ATT&CK Mapping</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {rules.map((rule) => {
                const isIcmpRule = rule.rule_id === 'RULE_06' || rule.rule_id === 'RULE_07';
                return (
                  <tr key={rule.rule_id} className={`hover:bg-gray-800/30 transition ${isIcmpRule ? 'bg-cyan-950/10' : ''}`}>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${
                        isIcmpRule 
                          ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40' 
                          : 'bg-gray-900 text-slate-300 border-gray-700'
                      }`}>
                        {rule.rule_id}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <div className="font-semibold text-white">{rule.name}</div>
                      <p className="text-[11px] text-slate-400 mt-0.5 max-w-md">{rule.description}</p>
                    </td>
                    <td className="py-3 px-3 text-slate-300 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-gray-900/80 border border-gray-800 text-[11px]">
                        {rule.category}
                      </span>
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td className="py-3 px-3 text-slate-300 whitespace-nowrap">
                      <span className="flex items-center gap-1.5">
                        {isIcmpRule && <Radio className="w-3 h-3 text-cyan-400" />}
                        <span>{rule.source}</span>
                      </span>
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      {isIcmpRule ? (
                        <span className="text-[11px] text-slate-400 italic">
                          {rule.mitre_id}
                        </span>
                      ) : (
                        <a
                          href={`https://attack.mitre.org/techniques/${rule.mitre_id}/`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 font-bold"
                        >
                          <span>{rule.mitre_id} — {rule.mitre_name}</span>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* =========================================================================
          MITRE ATT&CK TECHNIQUE NAVIGATOR (PHASE 3)
          ========================================================================= */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-bold text-white tracking-wide">MITRE ATT&CK® Enterprise Matrix</h3>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Reference database of adversary techniques, tactics, and mitigations.
            </p>
          </div>

          {/* Filter & Search */}
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative">
              <input
                type="text"
                placeholder="Search technique ID or name..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="bg-black/50 border border-gray-700 rounded-lg pl-8 pr-4 py-1.5 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-full sm:w-60"
              />
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            </div>

            <select
              value={tacticFilter}
              onChange={(e) => setTacticFilter(e.target.value)}
              className="bg-black/50 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">ALL TACTICS</option>
              {tactics.map(tac => (
                <option key={tac} value={tac}>{tac}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Techniques Grid */}
        {loading ? (
          <LoadingSpinner message="Loading MITRE techniques from PostgreSQL..." />
        ) : error ? (
          <ErrorMessage message={error} onRetry={loadData} />
        ) : filteredTechniques.length === 0 ? (
          <EmptyState
            title="No techniques found"
            description="No registered MITRE techniques match your query."
          />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {filteredTechniques.map((tech) => (
              <div
                key={tech.technique_id}
                className="p-5 rounded-xl soc-glass border border-gray-800 hover:border-cyan-500/40 transition space-y-3 flex flex-col justify-between"
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-cyan-400 px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800">
                      {tech.technique_id}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-800">
                      {tech.tactic}
                    </span>
                  </div>

                  <h3 className="text-sm font-semibold text-white">{tech.name}</h3>

                  <p className="text-xs text-slate-400 font-mono leading-relaxed line-clamp-4">
                    {tech.description || 'No description logged.'}
                  </p>
                </div>

                <div className="pt-3 border-t border-gray-800/80 flex items-center justify-between text-[11px] font-mono">
                  <a
                    href={`https://attack.mitre.org/techniques/${tech.technique_id}/`}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 transition"
                  >
                    <span>Official MITRE Guide</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

    </div>
  );
}
