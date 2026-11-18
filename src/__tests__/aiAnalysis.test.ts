import { afterEach, describe, expect, it, vi } from 'vitest';
import { interpretAnalyzeResponse, runAiAnalysis } from '../lib/aiAnalysis';

const packet: any = { srcIp: '203.0.113.9', dstIp: '10.0.1.10', port: 443, protocol: 'HTTPS', vector: 'UNKNOWN', payload: "x') or 1=1" };

describe('ai-analyze response handling', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('a 200 with a verdict is a result, with the detection the server measured', () => {
    const o = interpretAnalyzeResponse(200, {
      verdict: 'BLOCK', threatScore: 80, isFallbackMode: true,
      detection: { engine: 'LOCAL_PAYLOAD_CLASSIFIER', family: 'SQL_INJECTION', score: 80, signatures: ['boolean test between two constants'], entropy: 3.1 }
    });
    expect(o.kind).toBe('ok');
    if (o.kind === 'ok') expect(o.result.detection?.signatures).toEqual(['boolean test between two constants']);
  });

  it('413 is an error with the server code, not an analysis', () => {
    const o = interpretAnalyzeResponse(413, { error: 'PAYLOAD_TOO_LARGE', message: 'too big', messageAr: 'كبير' });
    expect(o).toMatchObject({ kind: 'error', status: 413, code: 'PAYLOAD_TOO_LARGE', message: 'too big', messageAr: 'كبير' });
  });

  it('429 and 400 are errors too', () => {
    expect(interpretAnalyzeResponse(429, { error: 'AGENT_SELF_DOS_DEFENSE_TRIGGERED' })).toMatchObject({ kind: 'error', code: 'AGENT_SELF_DOS_DEFENSE_TRIGGERED' });
    expect(interpretAnalyzeResponse(400, { error: 'Missing packet payload for AI analysis' })).toMatchObject({ kind: 'error', status: 400 });
    expect(interpretAnalyzeResponse(502, null)).toMatchObject({ kind: 'error', code: 'HTTP_502' });
  });

  it('a 200 without a verdict is malformed, not a pass', () => {
    expect(interpretAnalyzeResponse(200, { threatScore: 4 })).toMatchObject({ kind: 'error', code: 'MALFORMED_RESPONSE' });
  });

  it('a network failure is reported as such and invents no verdict', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
    const o = await runAiAnalysis(packet);
    expect(o).toMatchObject({ kind: 'error', status: null, code: 'NETWORK' });
    // The old handler returned verdict BLOCK, score 96 and "deep AI inspection confirmed zero-day".
    expect(JSON.stringify(o)).not.toMatch(/BLOCK|96|zero-day/);
  });

  it('a non-JSON body on an error status is still a clean error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('<html>bad gateway</html>', { status: 502 })));
    expect(await runAiAnalysis(packet)).toMatchObject({ kind: 'error', status: 502, code: 'HTTP_502' });
  });
});
