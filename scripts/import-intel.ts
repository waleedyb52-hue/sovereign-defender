/**
 * THREAT INTEL IMPORTER
 *
 * Loads public threat-intelligence corpora into the local store so the AI has
 * something substantial to retrieve from.
 *
 * On sovereignty: importing is a DELIBERATE, one-off operator action that
 * downloads to local disk. That is categorically different from the platform
 * phoning out at analysis time — after an import the corpus is local and the
 * runtime still makes zero external calls. Nothing here runs automatically.
 * Every source can also be imported from a file you downloaded elsewhere, so
 * a genuinely air-gapped deployment never needs this script to touch a network.
 *
 * Usage (from the repo root):
 *   npx tsx scripts/import-intel.ts --mitre            # ATT&CK techniques (~48MB download)
 *   npx tsx scripts/import-intel.ts --kev              # CISA known-exploited vulns
 *   npx tsx scripts/import-intel.ts --threatfox        # recent malicious indicators
 *   npx tsx scripts/import-intel.ts --all
 *   npx tsx scripts/import-intel.ts --mitre --from ./enterprise-attack.json   # offline
 */

import fs from 'fs';
import { globalThreatMemory } from '../server/services/threatMemory.service.js';

const SOURCES = {
  mitre: 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
  kev: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  threatfox: 'https://threatfox.abuse.ch/export/json/recent/',
  urlhaus: 'https://urlhaus.abuse.ch/downloads/json_recent/',
  feodo: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
  tor: 'https://check.torproject.org/torbulkexitlist',
  blocklistde: 'https://lists.blocklist.de/lists/all.txt',
  spamhaus: 'https://www.spamhaus.org/drop/drop_v4.json'
};

const args = process.argv.slice(2);
const has = (f: string) => args.includes(f);
const valueOf = (f: string) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };

/** Fetches a plain-text feed (one indicator per line). */
async function loadText(name: keyof typeof SOURCES): Promise<string> {
  const fromFile = valueOf('--from');
  if (fromFile) {
    console.log(`  reading local file ${fromFile}`);
    return fs.readFileSync(fromFile, 'utf-8');
  }
  console.log(`  downloading ${SOURCES[name]}`);
  const res = await fetch(SOURCES[name], { headers: { 'User-Agent': 'SovereignDefender-IntelImporter' } });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${SOURCES[name]}`);
  return res.text();
}

async function load(name: keyof typeof SOURCES): Promise<any> {
  const fromFile = valueOf('--from');
  if (fromFile) {
    console.log(`  reading local file ${fromFile}`);
    return JSON.parse(fs.readFileSync(fromFile, 'utf-8'));
  }
  console.log(`  downloading ${SOURCES[name]}`);
  const res = await fetch(SOURCES[name], { headers: { 'User-Agent': 'SovereignDefender-IntelImporter' } });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${SOURCES[name]}`);
  return res.json();
}

/** MITRE publishes ATT&CK as STIX 2.x; techniques are `attack-pattern` objects. */
async function importMitre() {
  console.log('\n[MITRE ATT&CK] technique catalogue');
  const bundle = await load('mitre');
  const objects: any[] = bundle.objects || [];

  // Mitigations are separate objects linked by `mitigates` relationships.
  const mitigationById = new Map<string, string>();
  for (const o of objects) {
    if (o.type === 'course-of-action' && o.id) mitigationById.set(o.id, o.name);
  }
  const mitigationsFor = new Map<string, string[]>();
  for (const o of objects) {
    if (o.type === 'relationship' && o.relationship_type === 'mitigates' && o.target_ref?.startsWith('attack-pattern--')) {
      const name = mitigationById.get(o.source_ref);
      if (!name) continue;
      const list = mitigationsFor.get(o.target_ref) ?? [];
      list.push(name);
      mitigationsFor.set(o.target_ref, list);
    }
  }

  const rows = objects
    .filter(o => o.type === 'attack-pattern' && !o.x_mitre_deprecated && !o.revoked)
    .map(o => {
      const ext = (o.external_references || []).find((r: any) => r.source_name === 'mitre-attack');
      return {
        id: ext?.external_id,
        name: o.name,
        tactic: (o.kill_chain_phases || []).map((p: any) => p.phase_name).join(', '),
        description: o.description,
        detection: o.x_mitre_detection,
        mitigations: (mitigationsFor.get(o.id) ?? []).join('; '),
        platforms: (o.x_mitre_platforms || []).join(', '),
        url: ext?.url,
        source: 'MITRE_ATTACK'
      };
    })
    .filter(r => r.id);

  const { imported } = globalThreatMemory.importTechniques(rows);
  console.log(`  -> ${imported} techniques stored (of ${rows.length} parsed)`);
}

async function importKev() {
  console.log('\n[CISA KEV] vulnerabilities exploited in the wild');
  const data = await load('kev');
  const rows: any[] = data.vulnerabilities || [];
  const { imported } = globalThreatMemory.importVulnerabilities(rows);
  console.log(`  -> ${imported} known-exploited vulnerabilities stored`);
}

async function importThreatfox() {
  console.log('\n[abuse.ch ThreatFox] recent malicious indicators');
  const data = await load('threatfox');
  // ThreatFox returns { "<id>": [ { ioc_value, ioc_type, threat_type, confidence_level, first_seen, ... } ] }
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
        firstSeen: e.first_seen,
        lastSeen: e.last_seen || e.first_seen,
        source: 'ABUSE_CH_THREATFOX',
        notes: e.malware_printable
      });
    }
  }
  const { imported } = globalThreatMemory.importIocs(rows);
  console.log(`  -> ${imported} indicators stored (of ${rows.length} parsed)`);
}

async function importUrlhaus() {
  console.log('\n[abuse.ch URLhaus] malware distribution URLs');
  const data = await load('urlhaus');
  const rows: any[] = [];
  for (const entries of Object.values<any>(data)) {
    for (const e of (Array.isArray(entries) ? entries : [entries])) {
      if (!e?.url) continue;
      rows.push({
        indicator: e.url,
        type: 'URL',
        category: e.threat || 'MALWARE_DOWNLOAD',
        confidence: e.url_status === 'online' ? 85 : 60,
        firstSeen: e.dateadded,
        lastSeen: e.dateadded,
        source: 'ABUSE_CH_URLHAUS',
        notes: Array.isArray(e.tags) ? e.tags.join(',') : undefined
      });
    }
  }
  const { imported } = globalThreatMemory.importIocs(rows);
  console.log(`  -> ${imported} malicious URLs stored (of ${rows.length} parsed)`);
}

async function importFeodo() {
  console.log('\n[abuse.ch Feodo Tracker] active botnet command-and-control servers');
  const data = await load('feodo');
  const rows = (Array.isArray(data) ? data : []).map((e: any) => ({
    indicator: e.ip_address,
    type: 'IP' as const,
    category: `C2_${e.malware || 'BOTNET'}`,
    // Live C2 infrastructure is about as high-confidence as an indicator gets.
    confidence: 95,
    firstSeen: e.first_seen,
    lastSeen: e.last_online || e.first_seen,
    source: 'ABUSE_CH_FEODO',
    notes: `port ${e.port ?? '?'} · ${e.malware ?? ''}`
  })).filter((r: any) => r.indicator);
  const { imported } = globalThreatMemory.importIocs(rows);
  console.log(`  -> ${imported} active C2 servers stored`);
}

async function importTor() {
  console.log('\n[Tor Project] exit-node list');
  const text = await loadText('tor');
  const rows = text.split(/\r?\n/).map(l => l.trim()).filter(l => /^\d+\.\d+\.\d+\.\d+$/.test(l))
    .map(ip => ({
      indicator: ip, type: 'IP' as const, category: 'TOR_EXIT_NODE',
      // Not malicious by itself — context that raises scrutiny, so kept low.
      confidence: 40, source: 'TOR_PROJECT', notes: 'Anonymised egress; treat as context, not a verdict'
    }));
  const { imported } = globalThreatMemory.importIocs(rows);
  console.log(`  -> ${imported} Tor exit nodes stored`);
}

async function importBlocklistDe() {
  console.log('\n[blocklist.de] hosts observed attacking public services');
  const text = await loadText('blocklistde');
  const rows = text.split(/\r?\n/).map(l => l.trim()).filter(l => /^\d+\.\d+\.\d+\.\d+$/.test(l))
    .slice(0, 50000)
    .map(ip => ({
      indicator: ip, type: 'IP' as const, category: 'ATTACK_SOURCE',
      confidence: 75, source: 'BLOCKLIST_DE'
    }));
  const { imported } = globalThreatMemory.importIocs(rows);
  console.log(`  -> ${imported} attacking hosts stored`);
}

async function importSpamhaus() {
  console.log('\n[Spamhaus DROP] hijacked / criminally controlled netblocks');
  const text = await loadText('spamhaus');
  // DROP ships as newline-delimited JSON with a metadata header line.
  const rows: any[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const o = JSON.parse(line);
      if (!o.cidr) continue;
      rows.push({
        indicator: o.cidr, type: 'IP' as const, category: 'HIJACKED_NETBLOCK',
        confidence: 90, source: 'SPAMHAUS_DROP', notes: o.sblid ? `SBL ${o.sblid}` : undefined
      });
    } catch { /* metadata line */ }
  }
  const { imported } = globalThreatMemory.importIocs(rows);
  console.log(`  -> ${imported} hijacked netblocks stored`);
}

(async () => {
  if (!args.length || has('--help')) {
    console.log(`
Threat intel importer — populates the local RAG corpus.

  --mitre       MITRE ATT&CK technique catalogue  (what techniques MEAN)
  --kev         CISA Known Exploited Vulnerabilities
  --threatfox   abuse.ch recent malicious indicators
  --urlhaus     abuse.ch malware distribution URLs
  --feodo       abuse.ch active botnet C2 servers
  --tor         Tor Project exit-node list (context, not a verdict)
  --blocklistde hosts observed attacking public services
  --spamhaus    Spamhaus DROP hijacked netblocks
  --all         all of the above
  --from FILE   import from a local file instead of downloading (air-gapped)

Examples:
  npx tsx scripts/import-intel.ts --all
  npx tsx scripts/import-intel.ts --mitre --from ./enterprise-attack.json
`);
    process.exit(0);
  }

  const started = Date.now();
  try {
    if (has('--mitre') || has('--all')) await importMitre();
    if (has('--kev') || has('--all')) await importKev();
    if (has('--threatfox') || has('--all')) await importThreatfox();
    if (has('--urlhaus') || has('--all')) await importUrlhaus();
    if (has('--feodo') || has('--all')) await importFeodo();
    if (has('--tor') || has('--all')) await importTor();
    if (has('--blocklistde') || has('--all')) await importBlocklistDe();
    if (has('--spamhaus') || has('--all')) await importSpamhaus();
  } catch (err: any) {
    console.error('\nImport failed:', err?.message || err);
    process.exit(1);
  }

  const s = globalThreatMemory.stats();
  console.log(`\nCorpus now: ${s.incidents} incidents · ${s.iocs} indicators · ${(s.sizeBytes / 1048576).toFixed(1)} MB`);
  console.log(`Completed in ${((Date.now() - started) / 1000).toFixed(1)}s`);
  process.exit(0);
})();
