import React, { createContext, useContext, useState, useEffect } from 'react';

const ThemeContext = createContext();

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem('soc-theme');
    return saved === 'light' ? 'light' : 'dark'; // Dark mode is default
  });

  useEffect(() => {
    const root = document.documentElement;
    root.setAttribute('data-theme', theme);
    if (theme === 'dark') {
      root.classList.add('dark');
      root.classList.remove('light');
    } else {
      root.classList.add('light');
      root.classList.remove('dark');
    }
    localStorage.setItem('soc-theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  // Dynamic colors for Recharts visualizations
  const chartColors = {
    tooltipBg: theme === 'light' ? '#FFFFFF' : '#111827',
    tooltipBorder: theme === 'light' ? '#E2E8F0' : '#374151',
    tooltipText: theme === 'light' ? '#0F172A' : '#F8FAFC',
    axisStroke: theme === 'light' ? '#64748B' : '#9CA3AF',
    gridStroke: theme === 'light' ? '#E2E8F0' : '#1F2937',
  };

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggleTheme, chartColors }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
}
