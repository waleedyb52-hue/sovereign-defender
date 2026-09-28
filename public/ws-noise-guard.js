/*
 * Suppresses WebSocket reconnect noise from the Vite dev client and the telemetry
 * socket. Served as a file rather than inline so the production Content-Security-Policy
 * can forbid inline script entirely.
 */
window.addEventListener('unhandledrejection', function(event) {
  if (
    event.reason?.message?.includes('WebSocket') ||
    event.reason?.includes?.('WebSocket') ||
    String(event.reason || '').includes('WebSocket') ||
    String(event.reason || '').includes('websocket')
  ) {
    event.preventDefault();
  }
});

window.addEventListener('error', function(event) {
  var msg = (event.message || '') + ' ' + (event.error?.message || '');
  if (msg.includes('WebSocket') || msg.includes('websocket')) {
    event.preventDefault();
  }
});

(function() {
  var origConsoleError = console.error;
  console.error = function() {
    var first = arguments[0];
    if (
      typeof first === 'string' &&
      (first.includes('[vite] failed to connect to websocket') ||
       first.includes('WebSocket closed without opened'))
    ) {
      return;
    }
    return origConsoleError.apply(console, arguments);
  };
})();
