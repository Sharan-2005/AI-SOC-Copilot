import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import DashboardLayout from './layouts/DashboardLayout';
import DashboardPage from './pages/DashboardPage';
import AlertsPage from './pages/AlertsPage';
import AlertDetailsPage from './pages/AlertDetailsPage';
import IncidentsPage from './pages/IncidentsPage';
import IncidentDetailsPage from './pages/IncidentDetailsPage';
import EventsPage from './pages/EventsPage';
import MitrePage from './pages/MitrePage';
import SystemHealthPage from './pages/SystemHealthPage';
import LogUploadPage from './pages/LogUploadPage';
import IcmpMonitorPage from './pages/IcmpMonitorPage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<DashboardLayout />}>
          <Route index element={<DashboardPage />} />
          <Route path="upload" element={<LogUploadPage />} />
          <Route path="icmp" element={<IcmpMonitorPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="alerts/:id" element={<AlertDetailsPage />} />
          <Route path="incidents" element={<IncidentsPage />} />
          <Route path="incidents/:id" element={<IncidentDetailsPage />} />
          <Route path="events" element={<EventsPage />} />
          <Route path="mitre" element={<MitrePage />} />
          <Route path="system" element={<SystemHealthPage />} />
          {/* Catch-all redirect to Dashboard */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
