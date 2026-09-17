import crypto from 'crypto';

// =============================================================================
// PAYLOAD FORENSICS PRIMITIVES (v1.0)
// Shared, side-effect-free mathematics used by both the in-transit inspector
// and the file DLP engine: Shannon entropy, magic-byte identification, and
// MIME/content-type reconciliation.
// =============================================================================

/** Entropy is computed over at most this prefix, matching the DLP spec. */
export const ENTROPY_SAMPLE_BYTES = 4096;

/**
 * Bits-per-byte threshold above which content is considered encrypted,
 * compressed, or packed rather than natural text.
 *
 * Rationale: English prose sits near 4.0-4.7, source code and JSON near
 * 4.5-5.5, already-compressed containers (zip/jpeg/png) near 7.9-8.0, and
 * AES/ChaCha ciphertext is statistically indistinguishable from uniform at
 * ~7.99. 7.2 sits above every realistic plaintext distribution while staying
 * below compressed and encrypted output.
 */
export const HIGH_ENTROPY_THRESHOLD = 7.2;

/**
 * Shannon entropy in bits per byte.
 *
 *     H(X) = - Σ  P(x_i) · log2( P(x_i) )
 *              i
 *
 * where P(x_i) is the empirical frequency of byte value i in the sample.
 * With 256 possible byte values the maximum is log2(256) = 8.0 bits/byte
 * (perfectly uniform), and the minimum is 0.0 (a single repeated byte).
 *
 * Only the first `ENTROPY_SAMPLE_BYTES` are considered, which bounds the cost
 * to a constant regardless of file size - essential for a check that runs
 * in-line on every operation.
 */
export function shannonEntropy(input: Buffer | string, sampleBytes: number = ENTROPY_SAMPLE_BYTES): number {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf-8');
  const sample = buffer.length > sampleBytes ? buffer.subarray(0, sampleBytes) : buffer;
  const n = sample.length;
  if (n === 0) return 0;

  // Single pass frequency histogram over the 256 byte values.
  const frequencies = new Uint32Array(256);
  for (let i = 0; i < n; i++) frequencies[sample[i]]++;

  let entropy = 0;
  for (let value = 0; value < 256; value++) {
    const count = frequencies[value];
    if (count === 0) continue; // P=0 contributes 0 to the sum; log2(0) is undefined.
    const p = count / n;
    entropy -= p * Math.log2(p);
  }

  // Clamp to the theoretical range to absorb floating point drift.
  return Number(Math.min(8, Math.max(0, entropy)).toFixed(4));
}

/** Renders the leading bytes as uppercase hex pairs, e.g. "4D 5A 90 00". */
export function magicBytesHex(input: Buffer | string, count: number = 8): string {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf-8');
  const slice = buffer.subarray(0, count);
  return Array.from(slice)
    .map(b => b.toString(16).padStart(2, '0').toUpperCase())
    .join(' ');
}

export interface MagicSignature {
  /** Hex prefix without separators, uppercase. */
  prefix: string;
  label: string;
  /** Broad class used for MIME reconciliation. */
  category: 'EXECUTABLE' | 'ARCHIVE' | 'IMAGE' | 'DOCUMENT' | 'SCRIPT';
  /** MIME types this signature legitimately corresponds to. */
  legitimateMimes: string[];
}

/**
 * Magic-byte table. Ordered longest-prefix-first so a more specific signature
 * always wins over a shorter one that happens to share its opening bytes.
 */
export const MAGIC_SIGNATURES: MagicSignature[] = [
  { prefix: '7F454C46', label: 'ELF executable', category: 'EXECUTABLE', legitimateMimes: ['application/x-executable', 'application/x-elf'] },
  { prefix: 'CAFEBABE', label: 'Java class / Mach-O fat binary', category: 'EXECUTABLE', legitimateMimes: ['application/java-vm'] },
  { prefix: 'FEEDFACE', label: 'Mach-O 32-bit executable', category: 'EXECUTABLE', legitimateMimes: ['application/x-mach-binary'] },
  { prefix: 'FEEDFACF', label: 'Mach-O 64-bit executable', category: 'EXECUTABLE', legitimateMimes: ['application/x-mach-binary'] },
  { prefix: '25504446', label: 'PDF document', category: 'DOCUMENT', legitimateMimes: ['application/pdf'] },
  { prefix: '89504E47', label: 'PNG image', category: 'IMAGE', legitimateMimes: ['image/png'] },
  { prefix: '47494638', label: 'GIF image', category: 'IMAGE', legitimateMimes: ['image/gif'] },
  { prefix: 'FFD8FF', label: 'JPEG image', category: 'IMAGE', legitimateMimes: ['image/jpeg', 'image/jpg'] },
  { prefix: '504B0304', label: 'ZIP / OOXML container', category: 'ARCHIVE', legitimateMimes: ['application/zip', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'] },
  { prefix: '1F8B', label: 'GZIP archive', category: 'ARCHIVE', legitimateMimes: ['application/gzip'] },
  { prefix: '377ABCAF', label: '7-Zip archive', category: 'ARCHIVE', legitimateMimes: ['application/x-7z-compressed'] },
  { prefix: '4D5A', label: 'PE/DOS executable', category: 'EXECUTABLE', legitimateMimes: ['application/x-msdownload', 'application/vnd.microsoft.portable-executable'] },
  { prefix: '2321', label: 'Interpreter shebang (#!)', category: 'SCRIPT', legitimateMimes: ['application/x-sh', 'text/x-shellscript'] }
];

/** Inline script/exploit markers that make a "document" executable in practice. */
export const EMBEDDED_SCRIPT_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /<\?php/i, label: 'PHP open tag' },
  { pattern: /<script[\s>]/i, label: 'HTML script tag' },
  { pattern: /eval\s*\(/i, label: 'eval() invocation' },
  { pattern: /base64_decode\s*\(/i, label: 'base64_decode() invocation' },
  { pattern: /system\s*\(|shell_exec\s*\(|passthru\s*\(/i, label: 'command execution primitive' },
  { pattern: /Runtime\.getRuntime\(\)\.exec/i, label: 'Java runtime exec' },
  { pattern: /powershell\s+-(enc|e)\b/i, label: 'encoded PowerShell' }
];

export interface MagicByteAnalysis {
  magicBytesHex: string;
  /** Identified signature, or null when the leading bytes match nothing known. */
  signature: MagicSignature | null;
  /** True when the declared MIME contradicts the actual leading bytes. */
  mimeSpoofed: boolean;
  /** True when the real content is executable regardless of the declared MIME. */
  executableContent: boolean;
  /** Embedded script markers found in the sample. */
  embeddedScripts: string[];
  detail: string;
}

/** Normalizes a hex string for prefix comparison. */
function normalizeHex(hex: string): string {
  return hex.replace(/[^0-9a-fA-F]/g, '').toUpperCase();
}

/**
 * Reconciles declared MIME type against the actual leading bytes and embedded
 * content markers.
 *
 * This is the core anti-spoofing check: an upload claiming `image/png` whose
 * bytes begin `4D 5A` is a Windows executable wearing an image's name, which
 * no legitimate client produces.
 */
export function analyzeMagicBytes(
  content: Buffer | string,
  declaredMime: string | undefined,
  precomputedHex?: string
): MagicByteAnalysis {
  const buffer = Buffer.isBuffer(content) ? content : Buffer.from(content ?? '', 'utf-8');
  const hexDisplay = precomputedHex ?? magicBytesHex(buffer);
  const flatHex = normalizeHex(precomputedHex ?? hexDisplay);

  const signature = MAGIC_SIGNATURES.find(s => flatHex.startsWith(s.prefix)) ?? null;

  // Scan a bounded text window for embedded executable markers.
  const textWindow = buffer.subarray(0, ENTROPY_SAMPLE_BYTES).toString('utf-8');
  const embeddedScripts = EMBEDDED_SCRIPT_PATTERNS
    .filter(p => p.pattern.test(textWindow))
    .map(p => p.label);

  const mime = (declaredMime ?? '').toLowerCase().trim();
  const executableContent = signature?.category === 'EXECUTABLE' || embeddedScripts.length > 0;

  let mimeSpoofed = false;
  let detail = signature ? 'Leading bytes identify ' + signature.label + '.' : 'Leading bytes match no known container signature.';

  if (mime && signature) {
    // A declared MIME that the signature does not vouch for is a mismatch.
    mimeSpoofed = !signature.legitimateMimes.includes(mime);
    if (mimeSpoofed) {
      detail = 'Declared MIME "' + mime + '" contradicts actual content: ' + signature.label + '.';
    }
  }

  if (embeddedScripts.length > 0 && /^(image|application\/pdf|text\/plain|video|audio)/.test(mime)) {
    mimeSpoofed = true;
    detail = 'Content declared "' + mime + '" carries executable markers: ' + embeddedScripts.join(', ') + '.';
  }

  return { magicBytesHex: hexDisplay, signature, mimeSpoofed, executableContent, embeddedScripts, detail };
}

// -----------------------------------------------------------------------
// Cryptographic helpers
// -----------------------------------------------------------------------

/**
 * Process-lifetime HMAC key.
 *
 * Derived from an operator-supplied secret when present, otherwise generated
 * randomly at boot. A random per-boot key is the safe default: it means
 * digests cannot be forged by an attacker who knows only the source code,
 * while still being stable for the lifetime of the process that issued them.
 */
const HMAC_KEY: Buffer = process.env.INTERCEPT_HMAC_SECRET
  ? crypto.createHash('sha256').update(process.env.INTERCEPT_HMAC_SECRET).digest()
  : crypto.randomBytes(32);

/** HMAC-SHA256 over the payload using the system-derived key. */
export function hmacSha256(payload: string): string {
  return crypto.createHmac('sha256', HMAC_KEY).update(payload).digest('hex');
}

export function sha256(payload: string): string {
  return crypto.createHash('sha256').update(payload).digest('hex');
}

/**
 * Constant-time digest comparison.
 *
 * A plain `===` on hex digests leaks position-of-first-difference through
 * timing, which is exactly the oracle an attacker needs to forge a signature
 * byte by byte.
 */
export function digestsEqual(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/** Canonical JSON with recursively sorted keys, for stable digests. */
export function canonicalize(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(v => canonicalize(v)).join(',') + ']';
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return '{' + entries.map(([k, v]) => JSON.stringify(k) + ':' + canonicalize(v)).join(',') + '}';
}

/** RFC 4122 version 4 UUID. */
export function uuidv4(): string {
  return crypto.randomUUID();
}
