import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// 1. Health Probe
export const checkHealth = async () => {
  const res = await api.get('/health');
  return res.data;
};

// 2. Dashboard Stats
export const fetchDashboardStats = async () => {
  const res = await api.get('/dashboard/stats');
  return res.data;
};

// 3. Events
export const fetchEvents = async (params = {}) => {
  const res = await api.get('/events', { params });
  return res.data;
};

export const fetchEventById = async (id) => {
  const res = await api.get(`/events/${id}`);
  return res.data;
};

export const createEvent = async (data) => {
  const res = await api.post('/events', data);
  return res.data;
};

// 4. Alerts
export const fetchAlerts = async (params = {}) => {
  const res = await api.get('/alerts', { params });
  return res.data;
};

export const fetchAlertById = async (id) => {
  const res = await api.get(`/alerts/${id}`);
  return res.data;
};

export const createAlert = async (data) => {
  const res = await api.post('/alerts', data);
  return res.data;
};

export const updateAlert = async (id, data) => {
  const res = await api.patch(`/alerts/${id}`, data);
  return res.data;
};

export const deleteAlert = async (id) => {
  const res = await api.delete(`/alerts/${id}`);
  return res.data;
};

// 5. Incidents
export const fetchIncidents = async (params = {}) => {
  const res = await api.get('/incidents', { params });
  return res.data;
};

export const fetchIncidentById = async (id) => {
  const res = await api.get(`/incidents/${id}`);
  return res.data;
};

export const createIncident = async (data) => {
  const res = await api.post('/incidents', data);
  return res.data;
};

export const updateIncident = async (id, data) => {
  const res = await api.patch(`/incidents/${id}`, data);
  return res.data;
};

// 6. MITRE ATT&CK & Detection Rules
export const fetchMitreTechniques = async () => {
  const res = await api.get('/mitre/techniques');
  return res.data;
};

export const fetchMitreTechnique = async (techniqueId) => {
  const res = await api.get(`/mitre/techniques/${techniqueId}`);
  return res.data;
};

export const fetchDetectionRules = async () => {
  const res = await api.get('/mitre/rules');
  return res.data;
};

// 7. Log Ingestion & Upload (Phase 4)
export const uploadLogFile = async (file) => {
  const formData = new FormData();
  formData.append('file', file);
  const res = await api.post('/logs/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    timeout: 180000, // 3 minutes timeout for bulk log processing
  });
  return res.data;
};

// 8. Attack Simulator (Phase 4 & Phase 5)
export const simulateAttack = async (scenario) => {
  const endpoint =
    scenario === 'brute_force'
      ? '/simulator/brute-force'
      : scenario === 'port_scan'
      ? '/simulator/port-scan'
      : scenario === 'icmp_flood'
      ? '/simulator/icmp-flood'
      : scenario === 'icmp_ddos'
      ? '/simulator/icmp-ddos'
      : '/simulator/web-attack';
  const res = await api.post(endpoint);
  return res.data;
};

// 9. System Management - Clear All SOC Operational Data
export const clearSocData = async () => {
  const res = await api.delete('/system/clear-data');
  return res.data;
};

// 10. Phase 5 - Live ICMP Monitoring & DoS/DDoS Detection
export const fetchIcmpStatus = async () => {
  const res = await api.get('/icmp/status');
  return res.data;
};

export const fetchIcmpStats = async () => {
  const res = await api.get('/icmp/stats');
  return res.data;
};

export const fetchIcmpEvents = async (params = {}) => {
  const res = await api.get('/icmp/events', { params });
  return res.data;
};

export const fetchIcmpInterfaces = async (includeAdvanced = false) => {
  const res = await api.get('/icmp/interfaces', { params: { include_advanced: includeAdvanced } });
  return res.data;
};

export const fetchActiveInterface = async () => {
  const res = await api.get('/icmp/active-interface');
  return res.data;
};

export const fetchDriverStatus = async () => {
  const res = await api.get('/icmp/driver-status');
  return res.data;
};

export const fetchProtectedTargets = async () => {
  const res = await api.get('/icmp/targets');
  return res.data;
};

export const updateProtectedTargets = async (targets = []) => {
  const res = await api.put('/icmp/targets', { targets });
  return res.data;
};

export const startIcmpMonitor = async (ifaceName = null, protectedTargets = null) => {
  const payload = { interface: ifaceName };
  if (protectedTargets) {
    payload.protected_targets = protectedTargets;
  }
  const res = await api.post('/icmp/start', payload);
  return res.data;
};

export const stopIcmpMonitor = async () => {
  const res = await api.post('/icmp/stop');
  return res.data;
};

export const simulateIcmpTraffic = async (scenario, options = {}) => {
  const res = await api.post('/icmp/simulate', {
    scenario,
    count: options.count || null,
    target_ip: options.target_ip || '127.0.0.1',
    attacker_ip: options.attacker_ip || '192.168.1.185',
  });
  return res.data;
};

export const resetIcmpStats = async () => {
  const res = await api.post('/icmp/reset');
  return res.data;
};

export default api;
