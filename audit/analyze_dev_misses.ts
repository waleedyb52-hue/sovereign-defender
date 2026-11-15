/**
 * DEV-HALF MISS ANALYSIS — structure of what the classifier misses, on the half that may be read
 *
 * Calls classifyPayload() in-process on data/external/httpparams_dev.csv (never the sealed
 * half; the script refuses any file whose name contains "sealed") and buckets the missed
 * attacks by structural feature. For each feature it also counts how many BENIGN dev values
 * carry it, which is the false-positive cost a rule keyed on that feature would start from.
 *
 * It prints counts only. The features are hypotheses to guide rule design, not rules.
 *
 * Run:  npx tsx audit/analyze_dev_misses.ts data/external/httpparams_dev.csv [out.json]
 */

import fs from 'fs';
import { classifyPayload } from '../server/services/payloadClassifier.service.js';

function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else quoted = false;
      } else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); rows.push(row); row = []; field = '';
    } else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

const file = process.argv[2];
if (!file || !fs.existsSync(file)) { console.error('Usage: npx tsx audit/analyze_dev_misses.ts <httpparams_dev.csv> [out.json]'); process.exit(2); }
if (/sealed/i.test(file)) { console.error('Refusing to analyse a sealed file.'); process.exit(2); }

const table = parseCsv(fs.readFileSync(file, 'utf-8')).filter(r => r.length >= 4);
const header = table.shift()!;
const [iP, iT, iL] = ['payload', 'attack_type', 'label'].map(h => header.indexOf(h));
const rows = table.map(r => ({ payload: r[iP], type: r[iT], malicious: r[iL] === 'anom' }));

/** Structural features. Deliberately generic: none contains a literal taken from a sample. */
const FEATURES: Array<[string, RegExp]> = [
  ['numeric comparison N=N after or/and/where/having', /\b(or|and|where|having)\b[\s(]*\d+\s*(=|<|>|<>|!=)\s*\d+/i],
  ['quote/paren break then or/and', /['")]\s*\)*\s*\b(or|and)\b/i],
  ['select ... from', /\bselect\b[\s\S]{0,200}\bfrom\b/i],
  ['select with function/case/subquery', /\bselect\b\s*(\(|case\b|count\s*\(|char\s*\(|chr\s*\()/i],
  ['order by / group by N', /\b(order|group)\s+by\s+\d+/i],
  ['stacked statement ;select|;declare|;exec|;waitfor|;begin|;call', /;\s*(select|declare|exec|execute|waitfor|begin|call|create|copy)\b/i],
  ['sql function call (char|chr|concat|cast|convert|elt|extractvalue|updatexml|...)', /\b(char|chr|concat|concat_ws|cast|convert|elt|extractvalue|updatexml|make_set|json_keys|row_number|regexp_substring|randomblob|generate_series|dbms_\w+|utl_\w+|ctxsys\.\w+|xmltype|procedure\s+analyse)\s*\(/i],
  ['time/heavy function (sleep|benchmark|waitfor|pg_sleep|dbms_lock|receive_message)', /\b(sleep|benchmark|pg_sleep|receive_message|dbms_lock\.sleep)\s*\(|\bwaitfor\s+delay\b/i],
  ['trailing sql comment', /(--\s?[\w ]{0,12}|#|\/\*)\s*$/],
  ['as ALIAS where', /\)\s*as\s+\w+\s+where\b/i],
  ['rlike / regexp / like with subquery', /\b(rlike|regexp|not\s+like|like)\b\s*\(?\s*(select|\()/i],
  ['in (select|char...)', /\bin\s*\(\s*\(?\s*(select|char\s*\()/i],
  ['hex literal 0x..', /\b0x[0-9a-f]{4,}\b/i],
  ['system catalog (all_users|sysibm|rdb\$|sysusers|domain.|information_schema|mysql.db|pg_|sqlite_)', /\b(all_users|sysibm\.\w+|rdb\$\w+|sysusers|sysobjects|syscolumns|information_schema\.\w+|mysql\.\w+|pg_\w+|sqlite_master|domain\.\w+|v\$\w+)\b/i]
];

const report: Record<string, any> = { file, rows: rows.length, byType: {} };
const benign = rows.filter(r => !r.malicious);
const fpNow = benign.filter(r => classifyPayload(r.payload).malicious).length;
report.benign = { n: benign.length, flaggedNow: fpNow };

for (const type of [...new Set(rows.filter(r => r.malicious).map(r => r.type))]) {
  const set = rows.filter(r => r.type === type);
  const missed = set.filter(r => !classifyPayload(r.payload).malicious);
  const nearMiss = missed.filter(r => classifyPayload(r.payload).score > 0).length;
  const features = FEATURES.map(([name, re]) => ({
    feature: name,
    missedWithFeature: missed.filter(r => re.test(r.payload)).length,
    benignWithFeature: benign.filter(r => re.test(r.payload)).length
  })).filter(f => f.missedWithFeature > 0).sort((a, b) => b.missedWithFeature - a.missedWithFeature);
  const anyFeature = missed.filter(r => FEATURES.some(([, re]) => re.test(r.payload))).length;
  report.byType[type] = {
    n: set.length, missed: missed.length, missedWithNonZeroScore: nearMiss,
    missedMatchingAnyFeature: anyFeature, missedMatchingNoFeature: missed.length - anyFeature, features
  };
}
report.benignMatchingAnyFeature = benign.filter(r => FEATURES.some(([, re]) => re.test(r.payload))).length;

if (process.argv[3]) fs.writeFileSync(process.argv[3], JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
