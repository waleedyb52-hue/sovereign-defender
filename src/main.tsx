import React, { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import { AuthGate } from './components/auth/AuthGate';
import { WALL_PANELS, type WallPanel } from './components/soc/tactical/wallChannel';
import './index.css';
import { initCalmMode } from './hooks/useLiveData';

/**
 * A wall screen (/?wall=<panel>) renders one theatre and nothing else, so it does not run
 * the full console's polling and state. It sits behind the same AuthGate.
 */
const WallView = React.lazy(() => import('./components/soc/tactical/WallView').then(m => ({ default: m.WallView })));
const wallParam = new URLSearchParams(window.location.search).get('wall');
const wallPanel = WALL_PANELS.some(p => p.id === wallParam) ? (wallParam as WallPanel) : null;
const wallLang = (() => {
  try {
    return localStorage.getItem('sd_lang') === 'en' ? 'en' : 'ar';
  } catch {
    return 'ar';
  }
})();

// Safely intercept and suppress sandbox environment WebSocket closed errors and Vite HMR warnings
if (typeof window !== 'undefined') {
  window.addEventListener('unhandledrejection', event => {
    if (
      event.reason?.message?.includes('WebSocket') ||
      event.reason?.includes?.('WebSocket') ||
      String(event.reason || '').includes('WebSocket') ||
      String(event.reason || '').includes('websocket')
    ) {
      event.preventDefault();
    }
  });

  window.addEventListener('error', event => {
    const message = event.message || '';
    if (
      message.includes('WebSocket closed without opened') ||
      message.includes('failed to connect to websocket') ||
      message.includes('WebSocket')
    ) {
      event.preventDefault();
    }
  });
}

initCalmMode();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AuthGate>
      {wallPanel ? (
        <React.Suspense fallback={<div className="min-h-screen bg-black" />}>
          <WallView panel={wallPanel} lang={wallLang} />
        </React.Suspense>
      ) : (
        <App />
      )}
    </AuthGate>
  </StrictMode>
);
