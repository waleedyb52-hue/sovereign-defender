import fs from 'fs';
import { globalThreatMemory } from './threatMemory.service.js';

/**
 * OPEN-SOURCE THREAT INTEL FEEDS
 *
 * One definition of each public corpus, shared by the CLI importer and the
 * in-app import control so the two can never drift apart.
 *
 * Every source here is open, free and keyless. Fetching one is a deliberate
 * operator action — nothing in this module runs on a timer, and `filePath`
 * lets an air-gapped deployment import from a file downloaded elsewhere
 * without the process touching a network.
 */

export type FeedId = 'mitre' | 'kev' | 'threatfox' | 'urlhaus' | 'feodo' | 'tor' | 'blocklistde' | 'spamhaus';

export interface FeedDefinition {
  id: FeedId;
  url: string;
  nameEn: string;
  nameAr: string;
  descEn: string;
  descAr: string;
  /** What the feed populates, for the UI to group by. */
  kind: 'techniques' | 'vulnerabilities' | 'indicators';
  /** Rough download weight, so the UI can warn before a large pull. */
  approxMb: number;
}

export const FEEDS: Record<FeedId, FeedDefinition> = {
  mitre: {
    id: 'mitre',
    url: 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
    nameEn: 'MITRE ATT&CK', nameAr: 'مصفوفة MITRE ATT&CK',
    descEn: 'Technique catalogue: what each TTP means, how to detect and mitigate it.',
    descAr: 'كتالوج التقنيات: معنى كل أسلوب وطريقة كشفه والتخفيف منه.',
    kind: 'techniques', approxMb: 48
  },
  kev: {
    id: 'kev',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    nameEn: 'CISA KEV', nameAr: 'ثغرات CISA المُستغَلّة',
    descEn: 'Vulnerabilities confirmed exploited in the wild.',
    descAr: 'ثغرات مؤكَّد استغلالها فعلياً في البرية.',
    kind: 'vulnerabilities', approxMb: 2
  },
  threatfox: {
    id: 'threatfox',
    url: 'https://threatfox.abuse.ch/export/json/recent/',
    nameEn: 'abuse.ch ThreatFox', nameAr: 'ThreatFox من abuse.ch',
    descEn: 'Recent malicious indicators tied to malware families.',
    descAr: 'مؤشّرات خبيثة حديثة مرتبطة بعائلات برمجيات ضارة.',
    kind: 'indicators', approxMb: 4
  },
  urlhaus: {
    id: 'urlhaus',
    url: 'https://urlhaus.abuse.ch/downloads/json_recent/',
    nameEn: 'abuse.ch URLhaus', nameAr: 'URLhaus من abuse.ch',
    descEn: 'URLs actively distributing malware.',
    descAr: 'روابط تُوزّع برمجيات خبيثة فعلياً.',
    kind: 'indicators', approxMb: 3
  },
  feodo: {
    id: 'feodo',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
    nameEn: 'abuse.ch Feodo Tracker', nameAr: 'Feodo Tracker',
    descEn: 'Live botnet command-and-control servers.',
    descAr: 'خوادم قيادة وسيطرة نشطة لشبكات البوت.',
    kind: 'indicators', approxMb: 1
  },
  tor: {
    id: 'tor',
    url: 'https://check.torproject.org/torbulkexitlist',
    nameEn: 'Tor exit nodes', nameAr: 'عُقد خروج Tor',
    descEn: 'Anonymised egress. Context that raises scrutiny — not a verdict.',
    descAr: 'مخارج مجهولة الهوية. سياق يرفع التدقيق — وليس حُكماً بالخبث.',
    kind: 'indicators', approxMb: 1
  },
  blocklistde: {
    id: 'blocklistde',
    url: 'https://lists.blocklist.de/lists/all.txt',
    nameEn: 'blocklist.de', nameAr: 'blocklist.de',
    descEn: 'Hosts observed attacking public services.',
    descAr: 'مضيفات رُصدت وهي تهاجم خدمات عامة.',
    kind: 'indicators', approxMb: 2
  },
  spamhaus: {
    id: 'spamhaus',
    url: 'https://www.spamhaus.org/drop/drop_v4.json',
    nameEn: 'Spamhaus DROP', nameAr: 'Spamhaus DROP',
    descEn: 'Hijacked and criminally controlled netblocks.',
    descAr: 'كتل شبكية مخطوفة أو تحت سيطرة إجرامية.',
    kind: 'indicators', approxMb: 1
  }
};

export interface ImportResult {
  feed: FeedId;
  imported: number;
  parsed: number;
  durationMs: number;
}

async function fetchJson(url: string, filePath?: string): Promise<any> {
  if (filePath) return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  const res = await fetch(url, { headers: { 'User-Agent': 'SovereignDefender-IntelImporter' } });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  return res.json();
}

async function fetchText(url: string, filePath?: string): Promise<string> {
  if (filePath) return fs.readFileSync(filePath, 'utf-8');
  const res = await fetch(url, { headers: { 'User-Agent': 'SovereignDefender-IntelImporter' } });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  return res.text();
}

/** Runs one feed end to end: fetch, parse, persist. */
export async function importFeed(feed: FeedId, filePath?: string): Promise<ImportResult> {
  const started = Date.now();
  const def = FEEDS[feed];
  if (!def) throw new Error(`Unknown feed: ${feed}`);

  let imported = 0;
  let parsed = 0;

  switch (feed) {
    case 'mitre': {
      const bundle = await fetchJson(def.url, filePath);
      const objects: any[] = bundle.objects || [];
      // Mitigations live in separate objects joined by `mitigates` relationships.
      const mitigationById = new Map<string, string>();
      for (const o of objects) if (o.type === 'course-of-action' && o.id) mitigationById.set(o.id, o.name);
      const mitigationsFor = new Map<string, string[]>();
      for (const o of objects) {
        if (o.type === 'relationship' && o.relationship_type === 'mitigates' && o.target_ref?.startsWith('attack-pattern--')) {
          const n = mitigationById.get(o.source_ref);
          if (!n) continue;
          const l = mitigationsFor.get(o.target_ref) ?? [];
          l.push(n);
          mitigationsFor.set(o.target_ref, l);
        }
      }
      const rows = objects
        .filter(o => o.type === 'attack-pattern' && !o.x_mitre_deprecated && !o.revoked)
        .map(o => {
          const ext = (o.external_references || []).find((r: any) => r.source_name === 'mitre-attack');
          return {
            id: ext?.external_id, name: o.name,
            tactic: (o.kill_chain_phases || []).map((p: any) => p.phase_name).join(', '),
            description: o.description, detection: o.x_mitre_detection,
            mitigations: (mitigationsFor.get(o.id) ?? []).join('; '),
            platforms: (o.x_mitre_platforms || []).join(', '),
            url: ext?.url, source: 'MITRE_ATTACK'
          };
        })
        .filter(r => r.id);
      parsed = rows.length;
      imported = globalThreatMemory.importTechniques(rows).imported;
      break;
    }

    case 'kev': {
      const data = await fetchJson(def.url, filePath);
      const rows: any[] = data.vulnerabilities || [];
      parsed = rows.length;
      imported = globalThreatMemory.importVulnerabilities(rows).imported;
      break;
    }

    case 'threatfox': {
      const data = await fetchJson(def.url, filePath);
      const rows: any[] = [];
      for (const entries of Object.values<any>(data)) {
        for (const e of (Array.isArray(entries) ? entries : [entries])) {
          if (!e?.ioc_value) continue;
          const t = String(e.ioc_type || '').toLowerCase();
          rows.push({
            indicator: String(e.ioc_value).split(':')[0],
            type: t.includes('hash') ? 'HASH' : t.includes('domain') ? 'DOMAIN' : t.includes('url') ? 'URL' : 'IP',
            category: e.threat_type || e.malware_printable || 'MALICIOUS',
            confidence: Number(e.confidence_level ?? 70),
            firstSeen: e.first_seen, lastSeen: e.last_seen || e.first_seen,
            source: 'ABUSE_CH_THREATFOX', notes: e.malware_printable
          });
        }
      }
      parsed = rows.length;
      imported = globalThreatMemory.importIocs(rows).imported;
      break;
    }

    case 'urlhaus': {
      const data = await fetchJson(def.url, filePath);
      const rows: any[] = [];
      for (const entries of Object.values<any>(data)) {
        for (const e of (Array.isArray(entries) ? entries : [entries])) {
          if (!e?.url) continue;
          rows.push({
            indicator: e.url, type: 'URL',
            category: e.threat || 'MALWARE_DOWNLOAD',
            confidence: e.url_status === 'online' ? 85 : 60,
            firstSeen: e.dateadded, lastSeen: e.dateadded,
            source: 'ABUSE_CH_URLHAUS',
            notes: Array.isArray(e.tags) ? e.tags.join(',') : undefined
          });
        }
      }
      parsed = rows.length;
      imported = globalThreatMemory.importIocs(rows).imported;
      break;
    }

    case 'feodo': {
      const data = await fetchJson(def.url, filePath);
      const rows = (Array.isArray(data) ? data : []).map((e: any) => ({
        indicator: e.ip_address, type: 'IP' as const,
        category: `C2_${e.malware || 'BOTNET'}`,
        // Live C2 infrastructure is about the highest-confidence class there is.
        confidence: 95,
        firstSeen: e.first_seen, lastSeen: e.last_online || e.first_seen,
        source: 'ABUSE_CH_FEODO', notes: `port ${e.port ?? '?'} · ${e.malware ?? ''}`
      })).filter((r: any) => r.indicator);
      parsed = rows.length;
      imported = globalThreatMemory.importIocs(rows).imported;
      break;
    }

    case 'tor': {
      const text = await fetchText(def.url, filePath);
      const rows = text.split(/\r?\n/).map(l => l.trim())
        .filter(l => /^\d+\.\d+\.\d+\.\d+$/.test(l))
        .map(ip => ({
          indicator: ip, type: 'IP' as const, category: 'TOR_EXIT_NODE',
          // Deliberately low: Tor egress is not malicious by itself, and
          // scoring it as if it were manufactures false positives.
          confidence: 40, source: 'TOR_PROJECT',
          notes: 'Anonymised egress; treat as context, not a verdict'
        }));
      parsed = rows.length;
      imported = globalThreatMemory.importIocs(rows).imported;
      break;
    }

    case 'blocklistde': {
      const text = await fetchText(def.url, filePath);
      const rows = text.split(/\r?\n/).map(l => l.trim())
        .filter(l => /^\d+\.\d+\.\d+\.\d+$/.test(l))
        .slice(0, 50000)
        .map(ip => ({
          indicator: ip, type: 'IP' as const, category: 'ATTACK_SOURCE',
          confidence: 75, source: 'BLOCKLIST_DE'
        }));
      parsed = rows.length;
      imported = globalThreatMemory.importIocs(rows).imported;
      break;
    }

    case 'spamhaus': {
      const text = await fetchText(def.url, filePath);
      // DROP ships as newline-delimited JSON with a metadata header line.
      const rows: any[] = [];
      for (const line of text.split(/\r?\n/)) {
        if (!line.trim()) continue;
        try {
          const o = JSON.parse(line);
          if (!o.cidr) continue;
          rows.push({
            indicator: o.cidr, type: 'IP' as const, category: 'HIJACKED_NETBLOCK',
            confidence: 90, source: 'SPAMHAUS_DROP',
            notes: o.sblid ? `SBL ${o.sblid}` : undefined
          });
        } catch { /* metadata line */ }
      }
      parsed = rows.length;
      imported = globalThreatMemory.importIocs(rows).imported;
      break;
    }
  }

  return { feed, imported, parsed, durationMs: Date.now() - started };
}
