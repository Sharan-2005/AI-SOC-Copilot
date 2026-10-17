import { useEffect } from 'react';

const SOC_REFRESH_EVENT = 'soc:data-cleared';

/**
 * Triggers a global event to notify all mounted pages that SOC operational
 * data has been cleared or altered, so they can re-fetch telemetry.
 */
export function triggerSocRefresh() {
  window.dispatchEvent(new CustomEvent(SOC_REFRESH_EVENT));
}

/**
 * Custom React hook to re-run page fetch functions whenever SOC data is cleared.
 * @param {Function} refreshFn - Function to execute on clear
 */
export function useSocRefresh(refreshFn) {
  useEffect(() => {
    if (!refreshFn) return;

    const handleRefresh = () => {
      try {
        refreshFn();
      } catch (err) {
        console.error('Error during SOC page refresh:', err);
      }
    };

    window.addEventListener(SOC_REFRESH_EVENT, handleRefresh);
    return () => {
      window.removeEventListener(SOC_REFRESH_EVENT, handleRefresh);
    };
  }, [refreshFn]);
}
