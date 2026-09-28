import { useCallback, useEffect, useState } from 'react';
import { z } from 'zod';

/**
 * MERKLE TREE — rebuilt in the browser from the server's own inputs.
 *
 * GET /api/v1/fim/merkle-inputs gives every baseline leaf (path + hash) and the file's hash
 * on disk now. This hook repeats the server's construction exactly —
 *   leaf   = sha256(path + ":" + baselineHash), leaves sorted
 *   parent = sha256(leftHex + rightHex), an odd node paired with itself
 * — with WebCrypto, and compares the result with the root the server reports. A match
 * means the console verified the commitment rather than displaying it.
 *
 * A file whose current hash differs from its baseline breaks its leaf and every node on
 * the way to the root: the committed root no longer describes what is on disk. The tree
 * keeps the baseline layout so the broken branch is drawn where it lives.
 */

const Inputs = z.object({
  construction: z.string(),
  root: z.string(),
  lastCalculated: z.string(),
  leaves: z.array(z.object({ path: z.string(), name: z.string(), baselineSha256: z.string(), currentSha256: z.string().nullable() }))
});

export interface MerkleNode {
  hash: string;
  broken: boolean;
  /** Leaf only: the file it commits to. */
  leaf?: { name: string; path: string; state: 'INTACT' | 'ALTERED' | 'DELETED' };
}

export interface MerkleView {
  levels: MerkleNode[][]; // levels[0] = leaves, last = [root]
  serverRoot: string;
  computedRoot: string;
  verified: boolean;
  lastCalculated: string;
  broken: number;
}

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function build(inputs: z.infer<typeof Inputs>): Promise<MerkleView | null> {
  if (inputs.leaves.length === 0) return null;
  const leaves: MerkleNode[] = await Promise.all(
    inputs.leaves.map(async l => {
      const state = l.currentSha256 == null ? 'DELETED' : l.currentSha256 === l.baselineSha256 ? 'INTACT' : 'ALTERED';
      return { hash: await sha256Hex(`${l.path}:${l.baselineSha256}`), broken: state !== 'INTACT', leaf: { name: l.name, path: l.path, state } };
    })
  );
  // Server sorts leaf hashes as strings.
  leaves.sort((a, b) => (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0));

  const levels: MerkleNode[][] = [leaves];
  let cur = leaves;
  while (cur.length > 1) {
    const next: MerkleNode[] = [];
    for (let i = 0; i < cur.length; i += 2) {
      const l = cur[i];
      const r = i + 1 < cur.length ? cur[i + 1] : cur[i];
      next.push({ hash: await sha256Hex(l.hash + r.hash), broken: l.broken || r.broken });
    }
    levels.push(next);
    cur = next;
  }
  return {
    levels,
    serverRoot: inputs.root,
    computedRoot: cur[0].hash,
    verified: cur[0].hash === inputs.root,
    lastCalculated: inputs.lastCalculated,
    broken: leaves.filter(l => l.broken).length
  };
}

export function useMerkleTree(pollMs = 6_000) {
  const [view, setView] = useState<MerkleView | null>(null);
  const [empty, setEmpty] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      if (!globalThis.crypto?.subtle) throw new Error('WebCrypto unavailable — the tree cannot be verified in this browser context');
      const res = await fetch('/api/v1/fim/merkle-inputs');
      if (!res.ok) throw new Error(`/api/v1/fim/merkle-inputs -> ${res.status}`);
      const v = await build(Inputs.parse(await res.json()));
      setView(v);
      setEmpty(v == null);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'merkle inputs unreachable');
    }
  }, []);

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), pollMs);
    return () => clearInterval(t);
  }, [load, pollMs]);

  return { view, empty, error };
}

export default useMerkleTree;
