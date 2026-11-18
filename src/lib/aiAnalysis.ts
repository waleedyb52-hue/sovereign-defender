import { z } from 'zod';
import type { TelemetryPacket } from '../types';

/**
 * Transport and validation for POST /api/v1/agent/ai-analyze, kept out of components.
 *
 * Two defects this replaces, both of the kind .clauderules §0 treats as a false negative:
 *   - a non-200 reply (400, 413, 429) was handed to the modal as if it were an analysis;
 *   - a network failure produced an invented verdict — BLOCK, score 96, "deep AI inspection
 *     confirmed zero-day" — for a request that never reached the server.
 * The caller now gets either a validated result or an explicit error, never a guess.
 */

const Detection = z.object({
  engine: z.string(),
  family: z.string(),
  score: z.number(),
  signatures: z.array(z.string()),
  entropy: z.number().optional()
});

export const AnalyzeResult = z
  .object({
    verdict: z.string(),
    threatScore: z.number().optional(),
    aiGenerated: z.boolean().optional(),
    isFallbackMode: z.boolean().optional(),
    detection: Detection.optional(),
    detectionLatencyMs: z.number().optional(),
    analysisEn: z.string().optional(),
    analysisAr: z.string().optional(),
    rules: z
      .object({ iptables: z.string().optional(), suricata: z.string().optional(), ebpf: z.string().optional() })
      .optional(),
    cached: z.boolean().optional()
  })
  .passthrough();

export type AnalyzeResultT = z.infer<typeof AnalyzeResult>;

export type AnalyzeOutcome =
  | { kind: 'ok'; result: AnalyzeResultT }
  | {
      kind: 'error';
      /** HTTP status, or null when the request never got a response. */
      status: number | null;
      code: string;
      message: string | null;
      messageAr: string | null;
    };

/** Turns a raw HTTP reply into an outcome. Pure, so it is tested without a server. */
export function interpretAnalyzeResponse(status: number, body: unknown): AnalyzeOutcome {
  const b = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === 'string' ? v : null);
  if (status < 200 || status >= 300) {
    return {
      kind: 'error',
      status,
      code: str(b.error) ?? `HTTP_${status}`,
      message: str(b.message),
      messageAr: str(b.messageAr)
    };
  }
  const parsed = AnalyzeResult.safeParse(body);
  if (!parsed.success) {
    return { kind: 'error', status, code: 'MALFORMED_RESPONSE', message: 'The server replied without a verdict.', messageAr: 'ردّ الخادم بلا حكم.' };
  }
  return { kind: 'ok', result: parsed.data };
}

export async function runAiAnalysis(packet: TelemetryPacket): Promise<AnalyzeOutcome> {
  let res: Response;
  try {
    res = await fetch('/api/v1/agent/ai-analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ packet })
    });
  } catch (err: any) {
    return {
      kind: 'error',
      status: null,
      code: 'NETWORK',
      message: err?.message ?? 'The request did not reach the server.',
      messageAr: 'لم يصل الطلب إلى الخادم.'
    };
  }
  const body = await res.json().catch(() => null);
  return interpretAnalyzeResponse(res.status, body);
}
