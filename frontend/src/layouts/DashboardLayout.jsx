import React, { useState, useEffect } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  AlertTriangle, 
  ShieldAlert, 
  Activity, 
  Grid, 
  Server, 
  Shield, 
  Menu, 
  X,
  RefreshCw,
  Database,
  UploadCloud,
  Moon,
  Sun,
  Trash2,
  Radio
} from 'lucide-react';
import { checkHealth } from '../services/api';
import { useTheme } from '../context/ThemeContext';
import ClearDataModal from '../components/ClearDataModal';

const NAV_ITEMS = [
  { path: '/', label: 'Overview', icon: LayoutDashboard },
  { path: '/upload', label: 'Upload Logs', icon: UploadCloud },
  { path: '/icmp', label: 'Live Network Monitor', icon: Radio },
  { path: '/alerts', label: 'Alerts', icon: AlertTriangle },
  { path: '/incidents', label: 'Incidents', icon: ShieldAlert },
  { path: '/events', label: 'Event Stream', icon: Activity },
  { path: '/mitre', label: 'MITRE ATT&CK', icon: Grid },
  { path: '/system', label: 'System Health', icon: Server },
];

export default function DashboardLayout() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [dbConnected, setDbConnected] = useState(false);
  const [checking, setChecking] = useState(false);
  const [clearModalOpen, setClearModalOpen] = useState(false);
  const location = useLocation();
  const { theme, toggleTheme } = useTheme();

  const probeStatus = async () => {
    setChecking(true);
    try {
      const data = await checkHealth();
      setDbConnected(data?.database?.connected === true);
    } catch {
      setDbConnected(false);
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => {
    probeStatus();
    const interval = setInterval(probeStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-[#0B0F19] text-slate-100 soc-grid-bg flex font-sans transition-colors duration-200">
      
      {/* Sidebar - Desktop */}
      <aside className="hidden lg:flex flex-col w-64 border-r border-gray-800 bg-[#111827]/90 backdrop-blur-md sticky top-0 h-screen z-40 transition-colors duration-200">
        
        {/* Brand */}
        <div className="h-16 flex items-center px-6 border-b border-gray-800 space-x-3">
          <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h1 className="font-bold text-sm tracking-wide text-white">AI SOC Copilot</h1>
            <p className="text-[10px] font-mono text-cyan-400 uppercase">Defense Console</p>
          </div>
        </div>

        {/* Navigation items */}
        <nav className="flex-1 px-3 py-6 space-y-1.5 overflow-y-auto">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) =>
                  `flex items-center space-x-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-950'
                      : 'text-slate-400 hover:text-white hover:bg-gray-800/60'
                  }`
                }
              >
                <Icon className="w-4 h-4" />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </nav>

        {/* Bottom System Status */}
        <div className="p-4 border-t border-gray-800 bg-black/20 text-xs font-mono space-y-2">
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5 text-purple-400" />
              Supabase DB:
            </span>
            <span className={`inline-flex items-center gap-1 font-semibold ${
              dbConnected ? 'text-emerald-400' : 'text-amber-400'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${dbConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
              {dbConnected ? 'ONLINE' : 'STANDBY'}
            </span>
          </div>
          <div className="text-[10px] text-slate-500 text-center">
            BE Information Technology
          </div>
        </div>
      </aside>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm" onClick={() => setMobileMenuOpen(false)} />
          <div className="relative w-64 bg-[#111827] border-r border-gray-800 h-full flex flex-col z-10 transition-colors duration-200">
            <div className="h-16 flex items-center justify-between px-6 border-b border-gray-800">
              <div className="flex items-center space-x-3">
                <Shield className="w-5 h-5 text-cyan-400" />
                <span className="font-bold text-sm text-white">AI SOC Copilot</span>
              </div>
              <button onClick={() => setMobileMenuOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
              {NAV_ITEMS.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    end={item.path === '/'}
                    onClick={() => setMobileMenuOpen(false)}
                    className={({ isActive }) =>
                      `flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium ${
                        isActive
                          ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                          : 'text-slate-400 hover:text-white hover:bg-gray-800/60'
                      }`
                    }
                  >
                    <Icon className="w-4 h-4" />
                    <span>{item.label}</span>
                  </NavLink>
                );
              })}
            </nav>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        
        {/* Top Header */}
        <header className="h-16 border-b border-gray-800 bg-[#111827]/70 backdrop-blur-md sticky top-0 z-30 px-4 sm:px-6 lg:px-8 flex items-center justify-between transition-colors duration-200">
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-2 rounded-lg text-slate-400 hover:text-white hover:bg-gray-800"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-cyan-400 font-semibold uppercase tracking-wider">
                SOC Console
              </span>
              <span className="text-slate-600">/</span>
              <span className="text-xs font-mono text-slate-300 capitalize">
                {location.pathname === '/' ? 'Overview' : location.pathname.split('/')[1]}
              </span>
            </div>
          </div>

          {/* Right Controls: Theme Toggle, Clear All Data, Status & Probe */}
          <div className="flex items-center space-x-2 sm:space-x-3">
            
            {/* Dark / Light Mode Toggle Button */}
            <button
              onClick={toggleTheme}
              className="p-2 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-slate-400 hover:text-cyan-400 transition flex items-center gap-1.5 text-xs font-mono"
              title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
              aria-label="Toggle Theme"
            >
              {theme === 'dark' ? (
                <>
                  <Sun className="w-4 h-4 text-amber-400" />
                  <span className="hidden md:inline text-[11px] text-slate-300">Light</span>
                </>
              ) : (
                <>
                  <Moon className="w-4 h-4 text-cyan-600" />
                  <span className="hidden md:inline text-[11px] text-slate-700">Dark</span>
                </>
              )}
            </button>

            {/* Clear All SOC Data Button */}
            <button
              onClick={() => setClearModalOpen(true)}
              className="px-2.5 py-1.5 sm:px-3 sm:py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 hover:text-red-300 transition flex items-center gap-1.5 text-xs font-mono font-medium shadow-sm"
              title="Clear all events, alerts, and incidents"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Clear All Data</span>
              <span className="sm:hidden">Reset</span>
            </button>

            {/* Supabase Connection Status Badge */}
            <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded-md bg-gray-900 border border-gray-800 text-[11px] font-mono text-slate-400">
              <span className={`w-2 h-2 rounded-full ${dbConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
              <span>Supabase {dbConnected ? 'Active' : 'Checking'}</span>
            </div>

            {/* Probe Refresh */}
            <button
              onClick={probeStatus}
              disabled={checking}
              className="p-2 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-slate-400 hover:text-cyan-400 transition"
              title="Refresh Connection Probe"
            >
              <RefreshCw className={`w-4 h-4 ${checking ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </header>

        {/* Dynamic Nested Page Content */}
        <main className="p-4 sm:p-6 lg:p-8 flex-1 overflow-x-hidden">
          <Outlet />
        </main>
      </div>

      {/* Confirmation Dialog for Destructive SOC Data Clear */}
      <ClearDataModal 
        isOpen={clearModalOpen} 
        onClose={() => setClearModalOpen(false)} 
      />
    </div>
  );
}
