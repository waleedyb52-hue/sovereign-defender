import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import zlib from 'zlib';

/**
 * SOVEREIGN OBJECT STORAGE
 *
 * Replicates the threat corpus to S3-compatible object storage.
 *
 * The sovereignty problem, and how this resolves it
 *   The platform's central claim is that nothing leaves the operator's
 *   control. Shipping the corpus to a commercial cloud bucket would break
 *   that claim outright, so two things are true of this service by design:
 *
 *   1. The intended target is MinIO, SeaweedFS or Ceph RGW — open-source,
 *      S3-compatible object storage the operator runs on their own hardware.
 *      That is "cloud storage" in capability while remaining infrastructure
 *      they own. It is the default in the shipped compose file.
 *
 *   2. Every object is encrypted with AES-256-GCM *before* it leaves the
 *      process, under a key that never goes into the request. So even if an
 *      operator deliberately points this at a commercial endpoint, the
 *      provider holds ciphertext and nothing else. Egress stops being a
 *      disclosure.
 *
 *   Replication is off unless explicitly configured, and never runs on its
 *   own schedule — an operator triggers it.
 *
 * Why SigV4 by hand rather than an SDK
 *   The same reasoning as using node:sqlite instead of a database server: the
 *   AWS SDK is a large dependency tree for what is, at bottom, an HMAC chain
 *   and a signed header. node:crypto covers it in a few dozen lines with no
 *   new supply chain to audit — which matters more than usual for a security
 *   product.
 */

export interface StorageConfig {
  endpoint: string;
  region: string;
  bucket: string;
  accessKey: string;
  secretKey: string;
  /** Path-style addressing, which MinIO and most self-hosted gateways need. */
  forcePathStyle: boolean;
}

export interface SyncResult {
  key: string;
  bytesRaw: number;
  bytesStored: number;
  encrypted: boolean;
  durationMs: number;
  endpoint: string;
}

export interface StorageStatus {
  configured: boolean;
  encrypted: boolean;
  endpoint?: string;
  bucket?: string;
  /** True when the endpoint is a private address the operator plausibly runs. */
  selfHosted?: boolean;
  lastSync?: { key: string; at: string; bytes: number } | null;
  reason?: string;
}

const AMZ_EMPTY_SHA256 = crypto.createHash('sha256').update('').digest('hex');

function hmac(key: crypto.BinaryLike | Buffer, data: string): Buffer {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest();
}

function sha256Hex(data: crypto.BinaryLike): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/** RFC 3986 encoding for the path segment; S3 is strict about this. */
function encodeKey(key: string): string {
  return key.split('/').map(seg => encodeURIComponent(seg).replace(/[!'()*]/g, c =>
    '%' + c.charCodeAt(0).toString(16).toUpperCase())).join('/');
}

/**
 * Private / link-local ranges. Used only to *report* whether the configured
 * endpoint looks self-hosted, so the UI can tell an operator plainly whether
 * their data is leaving the building. It never gates the request.
 */
function looksSelfHosted(endpoint: string): boolean {
  try {
    const host = new URL(endpoint).hostname;
    if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) return true;
    if (/^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host)) return true;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
    return false;
  } catch {
    return false;
  }
}

export class SovereignStorageService {
  private config: StorageConfig | null = null;
  private encryptionKey: Buffer | null = null;
  private lastSync: { key: string; at: string; bytes: number } | null = null;

  constructor() {
    this.loadConfig();
  }

  private loadConfig() {
    const endpoint = process.env.STORAGE_ENDPOINT;
    const bucket = process.env.STORAGE_BUCKET;
    const accessKey = process.env.STORAGE_ACCESS_KEY;
    const secretKey = process.env.STORAGE_SECRET_KEY;

    if (!endpoint || !bucket || !accessKey || !secretKey) {
      console.log('[Storage] Replication disabled — no endpoint configured. Corpus stays on local disk only.');
      return;
    }

    this.config = {
      endpoint: endpoint.replace(/\/+$/, ''),
      region: process.env.STORAGE_REGION || 'us-east-1',
      bucket,
      accessKey,
      secretKey,
      forcePathStyle: process.env.STORAGE_PATH_STYLE !== 'false'
    };

    // The encryption key is derived from a passphrase the operator holds. It
    // is never transmitted, so the storage provider cannot decrypt anything
    // it stores, whoever runs that provider.
    const passphrase = process.env.STORAGE_ENCRYPTION_KEY;
    if (passphrase) {
      this.encryptionKey = crypto.scryptSync(passphrase, 'sovereign-defender-corpus', 32);
    } else {
      console.warn(
        '[Storage] STORAGE_ENCRYPTION_KEY is not set. Objects would be stored as plaintext, ' +
        'so replication is REFUSED. Set a passphrase to enable it.'
      );
      // Refusing is the right default for a defence platform: silently
      // shipping an unencrypted threat corpus offsite is worse than not
      // replicating at all.
      this.config = null;
      return;
    }

    console.log(
      `[Storage] Replication ready -> ${this.config.endpoint}/${this.config.bucket} ` +
      `(${looksSelfHosted(this.config.endpoint) ? 'self-hosted' : 'EXTERNAL endpoint'}, AES-256-GCM before egress).`
    );
  }

  public status(): StorageStatus {
    if (!this.config) {
      return {
        configured: false,
        encrypted: false,
        reason: process.env.STORAGE_ENDPOINT
          ? 'STORAGE_ENCRYPTION_KEY missing — replication refused rather than sending plaintext.'
          : 'No storage endpoint configured. The corpus is local-only.'
      };
    }
    return {
      configured: true,
      encrypted: !!this.encryptionKey,
      endpoint: this.config.endpoint,
      bucket: this.config.bucket,
      selfHosted: looksSelfHosted(this.config.endpoint),
      lastSync: this.lastSync
    };
  }

  /** AES-256-GCM. Layout: [12-byte IV][16-byte auth tag][ciphertext]. */
  private encrypt(plain: Buffer): Buffer {
    if (!this.encryptionKey) throw new Error('No encryption key.');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const body = Buffer.concat([cipher.update(plain), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), body]);
  }

  public decrypt(blob: Buffer): Buffer {
    if (!this.encryptionKey) throw new Error('No encryption key.');
    const iv = blob.subarray(0, 12);
    const tag = blob.subarray(12, 28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(blob.subarray(28)), decipher.final()]);
  }

  /** AWS Signature V4 over a single PUT. */
  private sign(method: string, key: string, payloadHash: string, contentLength: number) {
    const cfg = this.config!;
    const url = new URL(cfg.endpoint);
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.slice(0, 8);

    const canonicalUri = cfg.forcePathStyle
      ? `/${cfg.bucket}/${encodeKey(key)}`
      : `/${encodeKey(key)}`;
    const host = cfg.forcePathStyle ? url.host : `${cfg.bucket}.${url.host}`;

    const headers: Record<string, string> = {
      'content-length': String(contentLength),
      'host': host,
      'x-amz-content-sha256': payloadHash,
      'x-amz-date': amzDate
    };
    const signedHeaders = Object.keys(headers).sort().join(';');
    const canonicalHeaders = Object.keys(headers).sort()
      .map(h => `${h}:${headers[h].trim()}\n`).join('');

    const canonicalRequest = [
      method, canonicalUri, '', canonicalHeaders, signedHeaders, payloadHash
    ].join('\n');

    const scope = `${dateStamp}/${cfg.region}/s3/aws4_request`;
    const stringToSign = [
      'AWS4-HMAC-SHA256', amzDate, scope, sha256Hex(canonicalRequest)
    ].join('\n');

    const signingKey = hmac(hmac(hmac(hmac(`AWS4${cfg.secretKey}`, dateStamp), cfg.region), 's3'), 'aws4_request');
    const signature = crypto.createHmac('sha256', signingKey).update(stringToSign, 'utf8').digest('hex');

    return {
      url: `${url.protocol}//${url.host}${canonicalUri}`,
      headers: {
        ...headers,
        'Authorization':
          `AWS4-HMAC-SHA256 Credential=${cfg.accessKey}/${scope}, ` +
          `SignedHeaders=${signedHeaders}, Signature=${signature}`
      }
    };
  }

  /** Uploads one object, gzip-compressed then encrypted. */
  public async putObject(key: string, plaintext: Buffer): Promise<SyncResult> {
    if (!this.config) throw new Error('Storage is not configured.');
    const started = Date.now();

    const compressed = zlib.gzipSync(plaintext, { level: 6 });
    const body = this.encrypt(compressed);
    const payloadHash = sha256Hex(body);

    const { url, headers } = this.sign('PUT', key, payloadHash, body.length);
    const res = await fetch(url, { method: 'PUT', headers, body: new Uint8Array(body) });

    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`Upload failed: HTTP ${res.status} ${detail.slice(0, 200)}`);
    }

    this.lastSync = { key, at: new Date().toISOString(), bytes: body.length };
    return {
      key,
      bytesRaw: plaintext.length,
      bytesStored: body.length,
      encrypted: true,
      durationMs: Date.now() - started,
      endpoint: this.config.endpoint
    };
  }

  /**
   * Replicates the corpus database as a point-in-time snapshot.
   *
   * The file is read as-is rather than streamed, because SQLite in WAL mode
   * can be copied consistently only between checkpoints; the caller is
   * expected to invoke this from an operator action, not mid-write.
   */
  public async syncCorpus(dbPath?: string): Promise<SyncResult> {
    const file = dbPath ?? path.join(process.cwd(), 'data', 'threat_memory.db');
    if (!fs.existsSync(file)) throw new Error(`Corpus not found at ${file}`);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    return this.putObject(`corpus/threat_memory_${stamp}.db.gz.enc`, fs.readFileSync(file));
  }

  /** Replicates an arbitrary JSON export (incidents, audit trail, report). */
  public async syncJson(name: string, payload: unknown): Promise<SyncResult> {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    return this.putObject(
      `exports/${name}_${stamp}.json.gz.enc`,
      Buffer.from(JSON.stringify(payload, null, 2), 'utf-8')
    );
  }
}

export const globalSovereignStorage = new SovereignStorageService();
