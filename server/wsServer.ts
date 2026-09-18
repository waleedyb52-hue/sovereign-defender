import { Server as HttpServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';

export class TelemetryWebSocketServer {
  private wss: WebSocketServer | null = null;
  private clients = new Set<WebSocket>();
  public broadcastRatePerSec: number = 0;
  private packetCountThisSec: number = 0;
  private startTime: number = Date.now();

  public init(server: HttpServer): void {
    try {
      this.wss = new WebSocketServer({ server, path: '/ws/telemetry' });

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
