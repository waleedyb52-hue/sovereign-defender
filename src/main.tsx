import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import './index.css';
import { initCalmMode } from './hooks/useLiveData';

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
    <App />
  </StrictMode>
);
