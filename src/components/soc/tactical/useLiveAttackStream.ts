import { useEffect, useRef, useState } from 'react';

/**
 * LIVE ATTACK STREAM
 *
 * Subscribes to the telemetry socket the platform already runs — `/ws/telemetry`,
 * served by `server/wsServer.ts` — using the same URL construction and the same
 * message contract as `KernelIngressPerformanceCenter`, which was the only client.
 * No path, port, protocol or message type is changed here; the cockpit is a second
 * reader of an existing feed.
 *
 * Message types, from the server:
 *   HANDSHAKE_INIT     sent once on connect
 *   TELEMETRY_PACKET   one inspected request, with a verdict
 *   REAL_EBPF_STATS    kernel counters, when a kernel path exists
 *
 * On failure this hook goes quiet rather than inventing traffic.
 *
 * That is the whole design decision. The obvious thing to do when a socket drops on a
 * live-looking radar is to keep the contacts moving so the screen does not look
 * broken — and that is precisely the defect rule 0 exists to forbid, in its most
 * dangerous form. A radar that animates fabricated packets tells an operator their
 * network is being watched when nothing is watching it. So `status` becomes
 * 'DISCONNECTED', the tracer list stops growing, and the theatre is expected to say
 * so on its face. A still radar that admits it is still is strictly safer than a
 * moving one that lies.
 */

export type StreamStatus = 'CONNECTING' | 'LIVE' | 'DISCONNECTED';

export interface Tracer {
  id: number;
  /** DROP, PASS, REDIRECT — the verdict the engine reached on this request. */
  verdict: 'DROP' | 'PASS' | 'REDIRECT';
  srcIp: string | null;
  country: string | null;
  at: number;
  threatType: string | null;
}

export interface KernelCounters {
  rxPackets: number | null;
  droppedPackets: number | null;
  passedPackets: number | null;
  avgLatencyNs: number | null;
  interfaceName: string | null;
  driverMode: string | null;
  blacklistEntries: number | null;
}

const MAX_TRACERS = 120;

export function useLiveAttackStream() {
  const [status, setStatus] = useState<StreamStatus>('CONNECTING');
  const [tracers, setTracers] = useState<Tracer[]>([]);
  const [kernel, setKernel] = useState<KernelCounters | null>(null);
  const [lastMessageAt, setLastMessageAt] = useState<number | null>(null);
  const [packetsSeen, setPacketsSeen] = useState(0);

  const idRef = useRef(0);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnect: ReturnType<typeof setTimeout> | null = null;
    let closed = false;

    const connect = () => {
      if (closed) return;
      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(`${protocol}//${window.location.host}/ws/telemetry`);

        // Handlers attached immediately: in a sandboxed preview the socket can fail
        // before the next statement runs, and an unattached error surfaces as an
        // unhandled rejection rather than a status change.
        ws.onerror = () => setStatus('DISCONNECTED');

        ws.onclose = () => {
          setStatus('DISCONNECTED');
          if (!closed) reconnect = setTimeout(connect, 6000);
        };

        ws.onopen = () => setStatus('LIVE');

        ws.onmessage = event => {
          try {
            const msg = JSON.parse(event.data);
            setLastMessageAt(Date.now());

            if (msg.type === 'REAL_EBPF_STATS' && msg.data) {
              const k = msg.data;
              setKernel({
                rxPackets: k.rxPackets ?? null,
                droppedPackets: k.droppedPackets ?? null,
                passedPackets: k.passedPackets ?? null,
                avgLatencyNs: k.avgLatencyNs ?? null,
                interfaceName: k.interfaceName ?? null,
                driverMode: k.driverMode ?? null,
                blacklistEntries: k.activeBlacklistEntries ?? null
              });
            }

            if (msg.type === 'TELEMETRY_PACKET' && msg.data) {
              const p = msg.data;
              const verdict: Tracer['verdict'] =
                p.status === 'BLOCKED' ? 'DROP' : p.status === 'HONEYPOT_DIVERTED' ? 'REDIRECT' : 'PASS';

              setPacketsSeen(n => n + 1);
              setTracers(prev => {
                const next = prev.concat({
                  id: ++idRef.current,
                  verdict,
                  srcIp: p.sourceIp ?? p.srcIp ?? null,
                  country: p.country ?? p.countryCode ?? null,
                  at: Date.now(),
                  threatType: p.threatType ?? p.attackType ?? null
                });
                return next.length > MAX_TRACERS ? next.slice(next.length - MAX_TRACERS) : next;
              });
            }
          } catch {
            // A malformed frame is dropped. It is not reported as traffic, because a
            // frame that could not be parsed is not an observation of anything.
          }
        };
      } catch {
        setStatus('DISCONNECTED');
        if (!closed) reconnect = setTimeout(connect, 6000);
      }
    };

    connect();

    return () => {
      closed = true;
      if (reconnect) clearTimeout(reconnect);
      ws?.close();
    };
  }, []);

  return { status, tracers, kernel, lastMessageAt, packetsSeen };
}

export default useLiveAttackStream;
