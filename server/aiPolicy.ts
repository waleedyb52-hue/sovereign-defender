/**
 * Sovereign Defender — outbound-AI / external-egress policy gate.
 *
 * The platform is marketed as a sovereign, on-premises SOC. To make that claim
 * literally true by default, ALL calls that leave the host — the Google Gemini
 * cloud model and any alert webhook (Telegram etc.) — are routed through this
 * single switch.
 *
 *   AI_CLOUD_ENABLED=true   → cloud reasoning + outbound webhooks permitted
 *   (anything else / unset)  → 100% on-premises: no external network calls,
 *                              the deterministic local hybrid engine serves.
 *
 * Centralising the decision here means containment cannot be re-opened by a
 * stray `process.env.GEMINI_API_KEY` check somewhere in the tree.
 */
export function isCloudAiEnabled(): boolean {
  return process.env.AI_CLOUD_ENABLED === 'true';
}

/**
 * The Gemini API key, but ONLY when cloud AI is explicitly enabled. When
 * containment is on this returns undefined, so every SDK init site that guards
 * on a truthy key transparently skips cloud initialisation and falls back to
 * the local engine — no per-call-site policy logic required.
 */
export function cloudAiApiKey(): string | undefined {
  return isCloudAiEnabled() ? process.env.GEMINI_API_KEY : undefined;
}

/**
 * Whether an outbound alert webhook (Telegram / generic HTTP) may fire.
 * Gated on the same switch so a sovereign deployment emits zero egress.
 */
export function isOutboundWebhookAllowed(): boolean {
  return isCloudAiEnabled();
}
