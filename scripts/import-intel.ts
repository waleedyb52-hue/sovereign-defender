/**
 * THREAT INTEL IMPORTER (CLI)
 *
 * Thin wrapper over server/services/intelFeeds.service.ts — the same code the
 * in-app import control runs, so the two can never drift.
 *
 * On sovereignty: importing is a DELIBERATE, one-off operator action that
 * downloads to local disk. That is categorically different from the platform
 * phoning out at analysis time — after an import the corpus is local and the
 * runtime still makes zero external calls. Nothing here runs on a schedule,
 * and --from imports a file you downloaded elsewhere, so a genuinely
 * air-gapped deployment never needs this to touch a network.
 *
 * Usage (from the repo root):
 *   npx tsx scripts/import-intel.ts --all
 *   npx tsx scripts/import-intel.ts --mitre --kev
 *   npx tsx scripts/import-intel.ts --mitre --from ./enterprise-attack.json
 */

import { FEEDS, importFeed, type FeedId } from '../server/services/intelFeeds.service.js';
import { globalThreatMemory } from '../server/services/threatMemory.service.js';

const args = process.argv.slice(2);
const has = (f: string) => args.includes(f);
const valueOf = (f: string) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };

const ALL: FeedId[] = Object.keys(FEEDS) as FeedId[];

(async () => {
  if (!args.length || has('--help')) {
    console.log('\nThreat intel importer — populates the local RAG corpus.\n');
    for (const id of ALL) {
      const f = FEEDS[id];
      console.log(`  --${id.padEnd(12)} ${f.nameEn.padEnd(24)} ${f.descEn}`);
    }
    console.log(`  --${'all'.padEnd(12)} every source above`);
    console.log(`  --${'from FILE'.padEnd(12)} import from a local file instead of downloading (air-gapped)\n`);
    process.exit(0);
  }

  const selected = has('--all') ? ALL : ALL.filter(id => has(`--${id}`));
  if (!selected.length) {
    console.error('No feed selected. Run with --help to list them.');
    process.exit(1);
  }

  const fromFile = valueOf('--from');
  if (fromFile && selected.length > 1) {
    console.error('--from applies to a single feed; select exactly one.');
    process.exit(1);
  }

  const started = Date.now();
  let failures = 0;

  for (const id of selected) {
    const f = FEEDS[id];
    console.log(`\n[${f.nameEn}] ${f.descEn}`);
    console.log(`  ${fromFile ? `reading ${fromFile}` : `downloading ${f.url}`}`);
    try {
      const r = await importFeed(id, fromFile);
      console.log(`  -> ${r.imported} stored (of ${r.parsed} parsed) in ${(r.durationMs / 1000).toFixed(1)}s`);
    } catch (err: any) {
      // One bad feed must not abort the rest of the run.
      console.error(`  !! failed: ${err?.message || err}`);
      failures++;
    }
  }

  const s = globalThreatMemory.stats();
  console.log(
    `\nCorpus: ${s.incidents} incidents · ${s.iocs} indicators · ${s.techniques} techniques · ` +
    `${s.vulnerabilities} vulnerabilities · ${(s.sizeBytes / 1048576).toFixed(1)} MB`
  );
  console.log(`Completed in ${((Date.now() - started) / 1000).toFixed(1)}s${failures ? ` (${failures} feed(s) failed)` : ''}`);
  process.exit(failures ? 1 : 0);
})();
