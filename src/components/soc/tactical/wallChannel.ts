import { useEffect, useRef } from 'react';

/**
 * WALL CHANNEL — keeps console windows on several screens in step.
 *
 * BroadcastChannel is same-origin and never leaves the browser: windows opened from this
 * console on the same machine hear each other, nothing crosses the network, and there is
 * no server state to go stale. Each window keeps its own session cookie (shared by the
 * origin), so a wall screen is exactly as authorised as the console that opened it.
 */

export type WallMessage = { type: 'select-ip'; ip: string } | { type: 'close-dossier' };

const NAME = 'sd-wall';

export function postWall(msg: WallMessage) {
  try {
    const ch = new BroadcastChannel(NAME);
    ch.postMessage(msg);
    ch.close();
  } catch {
    /* no BroadcastChannel: a single-screen console loses nothing */
  }
}

export function useWallChannel(onMessage: (msg: WallMessage) => void) {
  const handler = useRef(onMessage);
  handler.current = onMessage;
  useEffect(() => {
    let ch: BroadcastChannel | null = null;
    try {
      ch = new BroadcastChannel(NAME);
      ch.onmessage = e => handler.current(e.data as WallMessage);
    } catch {
      ch = null;
    }
    return () => ch?.close();
  }, []);
}

export type WallPanel = 'net' | 'net3d' | 'geo' | 'feed' | 'incident';

export const WALL_PANELS: Array<{ id: WallPanel; ar: string; en: string }> = [
  { id: 'net', ar: 'خريطة الشبكة', en: 'NETWORK MAP' },
  { id: 'net3d', ar: 'الشبكة ثلاثية الأبعاد', en: '3D NETWORK' },
  { id: 'geo', ar: 'المصادر العالمية', en: 'GLOBAL ORIGINS' },
  { id: 'feed', ar: 'تغذية التهديدات', en: 'THREAT FEED' },
  { id: 'incident', ar: 'لوحة الحادثة', en: 'INCIDENT BOARD' }
];

export function openWall(panel: WallPanel) {
  window.open(`/?wall=${panel}`, `sd-wall-${panel}`, 'popup,width=1600,height=900');
}
