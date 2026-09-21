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
  threatfox: 'https://threatfox.abuse.ch/export/json/recent/'
};

const args = process.argv.slice(2);
const has = (f: string) => args.includes(f);
const valueOf = (f: string) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };

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

(async () => {
  if (!args.length || has('--help')) {
    console.log(`
Threat intel importer — populates the local RAG corpus.

  --mitre       MITRE ATT&CK technique catalogue  (what techniques MEAN)
  --kev         CISA Known Exploited Vulnerabilities
  --threatfox   abuse.ch recent malicious indicators
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
  } catch (err: any) {
    console.error('\nImport failed:', err?.message || err);
    process.exit(1);
  }

  const s = globalThreatMemory.stats();
  console.log(`\nCorpus now: ${s.incidents} incidents · ${s.iocs} indicators · ${(s.sizeBytes / 1048576).toFixed(1)} MB`);
  console.log(`Completed in ${((Date.now() - started) / 1000).toFixed(1)}s`);
  process.exit(0);
})();
