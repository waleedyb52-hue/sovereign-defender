import type { Server as HttpServer, IncomingMessage } from 'http';
import type { Server as HttpsServer } from 'https';
import { WebSocketServer, WebSocket } from 'ws';

export class TelemetryWebSocketServer {
  private wss: WebSocketServer | null = null;
  private clients = new Set<WebSocket>();
  public broadcastRatePerSec: number = 0;
  private packetCountThisSec: number = 0;
  private startTime: number = Date.now();

  /**
   * `authorize` decides each upgrade before the socket opens. The stream carries every
   * live packet summary the console sees, so it needs the same credential as the API;
   * it was open to anyone who could reach the port. A refused upgrade gets 401 and no
   * socket.
   */
  public init(server: HttpServer | HttpsServer, authorize?: (req: IncomingMessage) => boolean): void {
    try {
      this.wss = new WebSocketServer({
        server,
        path: '/ws/telemetry',
        verifyClient: authorize ? (info, done) => (authorize(info.req) ? done(true) : done(false, 401, 'Unauthorized')) : undefined
      });

      this.wss.on('connection', (ws: WebSocket) => {
        this.clients.add(ws);

        // Send initial handshake
        ws.send(JSON.stringify({
          type: 'HANDSHAKE_INIT',
          server: 'Sovereign Defender High-Throughput Kernel Ingress Engine v4.0',
          timestamp: new Date().toISOString(),
          activeClients: this.clients.size
        }));

        ws.on('close', () => {
          this.clients.delete(ws);
        });

        ws.on('error', () => {
          this.clients.delete(ws);
        });
      });

      // Calculate broadcast rate every second
      setInterval(() => {
        this.broadcastRatePerSec = this.packetCountThisSec;
        this.packetCountThisSec = 0;
      }, 1000);

      console.log('[✓] WebSocket Telemetry Stream mounted at /ws/telemetry');
    } catch (err) {
      console.warn('WebSocket init warning:', err);
    }
  }

  public broadcast(type: string, data: any): void {
    if (!this.wss || this.clients.size === 0) return;

    this.packetCountThisSec++;
    const payload = JSON.stringify({
      type,
      timestamp: new Date().toISOString(),
      data
    });

    for (const client of this.clients) {
      if (client.readyState === WebSocket.OPEN) {
        try {
          client.send(payload);
        } catch (e) {
          // ignore closed socket
        }
      }
    }
  }

  public getStats() {
    return {
      connectedClients: this.clients.size,
      broadcastRatePerSec: this.broadcastRatePerSec,
      streamActive: this.clients.size > 0 || this.wss !== null,
      uptimeSec: Math.floor((Date.now() - this.startTime) / 1000)
    };
  }
}

export const globalTelemetryWsServer = new TelemetryWebSocketServer();
