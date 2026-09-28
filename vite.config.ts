import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig } from 'vite';

/** Where the defence backend listens. Overridable for a non-default local port. */
const BACKEND = process.env.SD_BACKEND_ORIGIN || 'http://127.0.0.1:3000';

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      /**
       * Without these two entries the dev server has no route to the backend.
       *
       * Every component fetches relative paths — `fetch('/api/v1/soc/analytics')` —
       * which resolve against the dev origin, not the API origin. Vite answered them
       * from its SPA fallback, so each request came back as index.html with a 200.
       * Zod then rejected the HTML and the hook counted the endpoint as silent, which
       * meant the consoles rendered their em dashes and empty states correctly while
       * the backend was healthy the whole time. A 200 from a SPA fallback is the
       * quietest possible failure: nothing logs, nothing throws, and the UI's honesty
       * about missing data is what ends up looking like the bug.
       *
       * `ws: true` covers /ws/telemetry, which upgrades rather than proxying plainly.
       *
       * ONLY for a standalone `vite` dev server. When server.ts embeds Vite as middleware
       * on port 3000, BACKEND *is* this server, so the proxy forwarded to itself: any
       * plain HTTP request beginning with /ws (a request, not an upgrade) was proxied
       * back into the same server, which proxied it again, without end. Three requests
       * left 24,482 sockets open — a one-line denial of service against the console.
       * server.ts sets SD_EMBEDDED_VITE, and the proxy is omitted.
       */
      proxy: process.env.SD_EMBEDDED_VITE
        ? undefined
        : {
            '/api': { target: BACKEND, changeOrigin: true },
            '/ws': { target: BACKEND, changeOrigin: true, ws: true },
          },
      hmr: {
        clientPort: 443,
        overlay: false,
      },
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
