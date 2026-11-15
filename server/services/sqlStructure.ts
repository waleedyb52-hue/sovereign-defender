/**
 * STRUCTURAL SQL-INJECTION ANALYSIS
 *
 * The signature rules in payloadClassifier.service.ts recognise SQL injection by fixed text:
 * a quote directly before OR/AND, the words UNION SELECT, four stacked verbs, four function
 * names followed by a parenthesis. Measured on the dev half of the external dataset that
 * misses 61% of SQL injection, and the misses are not exotic — they are ordinary sqlmap
 * output that differs from the signatures by a parenthesis or a missing quote:
 *
 *   -9650') or 1390=3209                 the quote is followed by ")" so the tautology rule fails
 *   1 and 9254=(select count(*) from …   no quote at all; SELECT without UNION is not a signature
 *   1"));waitfor delay '0:0:5'--         the time rule requires "(" after "waitfor delay"
 *   1) or 2633=dbms_pipe.receive_message(…   function not in the four-name list
 *
 * Adding one regex per variant would be writing rules against samples. This module asks a
 * different question of the payload: tokenised as SQL, does it contain SQL *syntax* — a
 * boolean test between two constants, a constant compared with a subquery, a SELECT followed
 * by an expression list, a stacked statement, a string or parenthesis context being closed
 * right before a SQL keyword. Those are properties of the injection technique, not of any
 * tool's output, and ordinary text does not have them: prose mentions SQL words, it does not
 * compare 6897 with 6897.
 *
 * Three tokenisations are tried, because an injected fragment usually starts INSIDE a string
 * literal of the original query: the text as given, and the text after its first single or
 * double quote. The reading with the strongest evidence is reported. (libinjection uses the
 * same idea; this is a small independent implementation, not a port.)
 *
 * Cost is bounded: at most MAX_LEN characters are examined, each pass is linear, and a
 * payload with none of the characters SQL syntax needs is rejected before tokenising.
 */

export interface SqlSignal {
  weight: number;
  label: string;
}

const MAX_LEN = 4096;

type Kind = 'num' | 'str' | 'id' | 'op' | 'lp' | 'rp' | 'semi' | 'comma' | 'quote' | 'cmt';
interface Tok { k: Kind; v: string }

const CMP_OPS = new Set(['=', '<', '>', '<>', '!=', '<=', '>=', '==']);
const CMP_WORDS = new Set(['like', 'rlike', 'regexp']);
const ARITH_OPS = new Set(['+', '-', '*', '/', '%']);
const BOOL_WORDS = new Set(['or', 'and', 'where', 'having', 'xor', 'when']);
/** Keywords that only make sense right after a closed string/parenthesis if the text is SQL. */
const BREAK_WORDS = new Set([
  'or', 'and', 'where', 'union', 'order', 'group', 'having', 'limit', 'into', 'procedure',
  'waitfor', 'rlike', 'like', 'in', 'select', 'xor'
]);

/** Functions with no meaning outside a SQL engine: one call is strong evidence. */
const STRONG_FUNCTIONS = new Set([
  'extractvalue', 'updatexml', 'pg_sleep', 'benchmark', 'randomblob', 'load_file', 'make_set',
  'elt', 'json_keys', 'generate_series', 'xmltype', 'regexp_substring', 'sleep', 'gtid_subset',
  'sqlid_to_sqlhash', 'group_concat', 'quotename'
]);
const STRONG_FUNCTION_PREFIX = /^(dbms_|utl_|ctxsys\.|xp_|sp_|sys\.dbms_|master\.\.)/;
/** Functions that also exist in other languages: only several together mean SQL. */
const GENERIC_FUNCTIONS = new Set([
  'char', 'chr', 'concat', 'concat_ws', 'cast', 'convert', 'substring', 'substr', 'mid',
  'ascii', 'ord', 'hex', 'unhex', 'upper', 'lower', 'count', 'length', 'md5', 'version',
  'user', 'database', 'ifnull', 'isnull', 'coalesce', 'nvl', 'repeat', 'right', 'left',
  'exp', 'floor', 'rand', 'row_number', 'str'
]);
/** System catalogs not already covered by the signature rule for information_schema. */
const CATALOG = /^(all_users|all_tables|all_tab_columns|user_tables|sysibm\.\w+|rdb\$\w+|sysusers|syscolumns|sys\.\w+|mysql\.(db|user)|sqlite_master|pg_(tables|user|shadow|database|class)|domain\.(domains|columns|tables)|v\$\w+|information_schema\.system_users)$/;

const STACKED_FOLLOW: Record<string, (next: Tok | undefined, after: Tok | undefined) => boolean> = {
  declare: n => !!n && n.k === 'id' && n.v.startsWith('@'),
  exec: n => !!n && (n.k === 'id' || n.k === 'lp'),
  execute: n => !!n && (n.k === 'id' || n.k === 'lp'),
  waitfor: n => !!n && n.k === 'id' && (n.v === 'delay' || n.v === 'time'),
  call: (n, a) => !!n && n.k === 'id' && !!a && a.k === 'lp',
  create: n => !!n && n.k === 'id' && ['table', 'function', 'procedure', 'user', 'or', 'trigger', 'view', 'database'].includes(n.v),
  copy: (n, a) => !!n && (n.k === 'id' || n.k === 'lp') && !!a,
  alter: n => !!n && n.k === 'id' && ['table', 'user', 'database', 'login'].includes(n.v),
  begin: n => !n || n.k === 'semi' || (n.k === 'id' && (n.v === 'declare' || n.v === 'if' || /[._]/.test(n.v))),
  shutdown: () => true,
  drop: n => !!n && n.k === 'id' && ['table', 'database', 'user', 'view', 'function', 'procedure'].includes(n.v),
  truncate: n => !!n && n.k === 'id' && n.v === 'table',
  delete: n => !!n && n.k === 'id' && n.v === 'from',
  insert: n => !!n && n.k === 'id' && n.v === 'into',
  update: (n, a) => !!n && n.k === 'id' && !!a && a.k === 'id' && a.v === 'set'
};

const isIdStart = (c: string) => (c >= 'a' && c <= 'z') || c === '_' || c === '@' || c === '$';
const isIdChar = (c: string) => isIdStart(c) || (c >= '0' && c <= '9') || c === '.' || c === '#';
const isDigit = (c: string) => c >= '0' && c <= '9';
const isHex = (c: string) => isDigit(c) || (c >= 'a' && c <= 'f');
const isSpace = (c: string) => c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v' || c === ' ';

/** Linear, allocation-light SQL-ish tokeniser over already lower-cased text. */
function tokenize(s: string): Tok[] {
  const out: Tok[] = [];
  const n = s.length;
  let i = 0;
  while (i < n) {
    const c = s[i];
    if (isSpace(c)) { i++; continue; }

    // Comments: "-- " or "--" at the end, "/* … */", and "#" when nothing but space follows.
    if (c === '-' && s[i + 1] === '-') {
      out.push({ k: 'cmt', v: '--' });
      const nl = s.indexOf('\n', i);
      i = nl === -1 ? n : nl + 1;
      continue;
    }
    if (c === '/' && s[i + 1] === '*') {
      out.push({ k: 'cmt', v: '/*' });
      const end = s.indexOf('*/', i + 2);
      i = end === -1 ? n : end + 2;
      continue;
    }
    if (c === '#') {
      let j = i + 1;
      while (j < n && isSpace(s[j])) j++;
      if (j >= n) { out.push({ k: 'cmt', v: '#' }); break; }
      i++;
      continue;
    }

    if (isDigit(c)) {
      let j = i;
      if (c === '0' && s[i + 1] === 'x' && i + 2 < n && isHex(s[i + 2])) {
        j = i + 2;
        while (j < n && isHex(s[j])) j++;
      } else {
        while (j < n && isDigit(s[j])) j++;
        if (s[j] === '.' && j + 1 < n && isDigit(s[j + 1])) { j++; while (j < n && isDigit(s[j])) j++; }
      }
      // "1337abc" is a word, not a number.
      if (j < n && isIdStart(s[j]) && s[j] !== '@' && s[j] !== '$') {
        while (j < n && isIdChar(s[j])) j++;
        out.push({ k: 'id', v: s.slice(i, j) });
      } else out.push({ k: 'num', v: s.slice(i, j) });
      i = j;
      continue;
    }

    if (isIdStart(c)) {
      let j = i + 1;
      while (j < n && isIdChar(s[j])) j++;
      let v = s.slice(i, j);
      while (v.length > 1 && v.endsWith('.')) v = v.slice(0, -1);
      out.push({ k: 'id', v });
      i = j;
      continue;
    }

    if (c === "'" || c === '"') {
      const close = s.indexOf(c, i + 1);
      if (close === -1) { out.push({ k: 'quote', v: c }); i++; }
      else { out.push({ k: 'str', v: s.slice(i + 1, close) }); i = close + 1; }
      continue;
    }

    if (c === '(') { out.push({ k: 'lp', v: c }); i++; continue; }
    if (c === ')') { out.push({ k: 'rp', v: c }); i++; continue; }
    if (c === ';') { out.push({ k: 'semi', v: c }); i++; continue; }
    if (c === ',') { out.push({ k: 'comma', v: c }); i++; continue; }

    const two = s.substr(i, 2);
    if (two === '||' || two === '&&' || two === '<>' || two === '!=' || two === '<=' || two === '>=' || two === '==') {
      out.push({ k: 'op', v: two }); i += 2; continue;
    }
    if ('=<>+-*/%~!|&^'.includes(c)) { out.push({ k: 'op', v: c }); i++; continue; }
    i++;
  }
  return out;
}

const isLit = (t: Tok | undefined) => !!t && (t.k === 'num' || t.k === 'str');
const isCmp = (t: Tok | undefined) => !!t && ((t.k === 'op' && CMP_OPS.has(t.v)) || (t.k === 'id' && CMP_WORDS.has(t.v)));
const isWord = (t: Tok | undefined, w: string) => !!t && t.k === 'id' && t.v === w;
const isCall = (t: Tok[], i: number) => t[i]?.k === 'id' && t[i + 1]?.k === 'lp';

/** Evidence found in one tokenisation. Labels are unique; the strongest weight per label wins. */
function analyseTokens(t: Tok[]): Map<string, number> {
  const found = new Map<string, number>();
  const add = (label: string, weight: number) => { if ((found.get(label) ?? 0) < weight) found.set(label, weight); };
  const skipOpen = (j: number) => { while (t[j]?.k === 'lp' || isWord(t[j], 'not')) j++; return j; };

  let depth = 0;
  const strongFns = new Set<string>();
  const genericFns = new Set<string>();
  let genericCalls = 0;

  for (let i = 0; i < t.length; i++) {
    const tok = t[i];

    // ── a string or parenthesis of the host query being closed right before a SQL keyword ──
    if (tok.k === 'lp') depth++;
    if (tok.k === 'quote' || (tok.k === 'rp' && depth === 0)) {
      let j = i + 1;
      while (t[j]?.k === 'rp' || t[j]?.k === 'quote') j++;
      const nx = t[j];
      if (nx && (nx.k === 'semi' || (nx.k === 'id' && BREAK_WORDS.has(nx.v)))) add('SQL context break before keyword', 20);
      if (isWord(nx, 'as') && t[j + 1]?.k === 'id' && isWord(t[j + 2], 'where')) add('SQL context break before keyword', 20);
    }
    if (tok.k === 'rp' && depth > 0) depth--;

    if (tok.k === 'num' && tok.v.startsWith('0x') && tok.v.length >= 10) add('long hex literal', 15);

    // ── constant compared with constant ──
    if (isLit(tok) && isCmp(t[i + 1])) {
      const k = skipOpen(i + 2);
      const rhs = t[k];
      const prev = t[i - 1];
      const sameKind = rhs && rhs.k === tok.k;
      const danglingString = tok.k === 'str' && rhs?.k === 'quote';
      const arithmeticBefore = prev?.k === 'op' && ARITH_OPS.has(prev.v);
      if ((sameKind || danglingString) && !arithmeticBefore) {
        // Find what introduces the comparison, looking back over opening parentheses.
        let b = i - 1;
        while (t[b]?.k === 'lp' || isWord(t[b], 'not')) b--;
        const intro = t[b];
        if (intro && intro.k === 'id' && BOOL_WORDS.has(intro.v)) add('boolean test between two constants', 60);
        else if (prev?.k === 'lp' && t[k + 1]?.k === 'rp') add('parenthesised constant comparison', 40);
        else add('constant comparison', 20);
      }
      // ── constant compared with a subquery or a function result ──
      if (rhs && (isWord(rhs, 'select') || isCall(t, k)) && !arithmeticBefore) add('constant compared with subquery or function', 55);
    }
    if (isLit(tok) && isWord(t[i + 1], 'in') && t[i + 2]?.k === 'lp') {
      const k = skipOpen(i + 2);
      if (isWord(t[k], 'select') || isCall(t, k)) add('constant compared with subquery or function', 55);
    }
    if (tok.k === 'id' && (CMP_WORDS.has(tok.v) || tok.v === 'in' || tok.v === 'exists') && t[i + 1]?.k === 'lp') {
      if (isWord(t[skipOpen(i + 1)], 'select')) add('predicate over a subquery', 55);
    }

    if (tok.k !== 'id') continue;

    // ── SELECT followed by an expression list ──
    if (tok.v === 'select') {
      let j = i + 1;
      while (isWord(t[j], 'all') || isWord(t[j], 'distinct') || isWord(t[j], 'top')) j++;
      const nx = t[j];
      const strong = !!nx && (
        nx.k === 'lp' || nx.k === 'num' || nx.k === 'str' ||
        (nx.k === 'op' && nx.v === '*') ||
        (nx.k === 'id' && (nx.v === 'case' || nx.v === 'null' || nx.v.startsWith('@') || t[j + 1]?.k === 'lp'))
      );
      if (strong) add('SELECT with expression list', 50);
      else if (nx?.k === 'id') {
        for (let f = j + 1; f < Math.min(t.length, j + 24); f++) {
          if (!isWord(t[f], 'from')) continue;
          const table = t[f + 1], after = t[f + 2];
          if (table?.k === 'id' && (!after || after.k === 'rp' || after.k === 'semi' || after.k === 'cmt' || after.k === 'comma' ||
              (after.k === 'id' && ['where', 'as', 'limit', 'order', 'group', 'union', 'and', 'or'].includes(after.v)))) {
            add('SELECT … FROM', 20);
          }
          break;
        }
      }
    }

    // ── stacked statement ──
    if (t[i - 1]?.k === 'semi') {
      const follow = STACKED_FOLLOW[tok.v];
      if (follow && follow(t[i + 1], t[i + 2])) add('stacked SQL statement (structural)', 55);
    }

    if (tok.v === 'waitfor' && (isWord(t[i + 1], 'delay') || isWord(t[i + 1], 'time'))) add('WAITFOR DELAY', 60);
    if (tok.v === 'into' && (isWord(t[i + 1], 'outfile') || isWord(t[i + 1], 'dumpfile'))) add('INTO OUTFILE', 60);
    if (tok.v === 'procedure' && isWord(t[i + 1], 'analyse')) add('PROCEDURE ANALYSE', 55);
    if ((tok.v === 'order' || tok.v === 'group') && isWord(t[i + 1], 'by') && t[i + 2]?.k === 'num') add('ORDER/GROUP BY column index', 20);
    if (tok.v === 'in' && isWord(t[i + 1], 'boolean') && isWord(t[i + 2], 'mode')) add('IN BOOLEAN MODE', 20);
    if (tok.v === 'case' && isWord(t[i + 1], 'when')) {
      for (let f = i + 2; f < Math.min(t.length, i + 24); f++) if (isWord(t[f], 'then')) { add('CASE WHEN … THEN', 45); break; }
    }
    if (tok.v === 'dual' && isWord(t[i - 1], 'from')) add('FROM DUAL', 30);
    // Only where a table name can stand. "all_users" is also a directory name in a URL path.
    if (CATALOG.test(tok.v)) {
      const before = t[i - 1];
      if (before && (before.k === 'comma' || (before.k === 'id' && ['from', 'join', 'into', 'update', 'table'].includes(before.v)))) {
        add('system catalog reference', 45);
      }
    }

    if (t[i + 1]?.k === 'lp') {
      if (STRONG_FUNCTIONS.has(tok.v) || STRONG_FUNCTION_PREFIX.test(tok.v)) strongFns.add(tok.v);
      // An empty call such as count() is how prose names a function; an injection passes arguments.
      else if (GENERIC_FUNCTIONS.has(tok.v) && t[i + 2] && t[i + 2].k !== 'rp') { genericFns.add(tok.v); genericCalls++; }
    }
  }

  if (strongFns.size) add(`SQL-only function call (${[...strongFns].slice(0, 3).join(', ')})`, strongFns.size > 1 ? 70 : 55);
  // Kept under the prose floor on purpose: these names exist in every language.
  if (genericFns.size >= 2 || genericCalls >= 3) add(`several SQL function calls (${[...genericFns].slice(0, 3).join(', ')})`, 35);
  else if (genericFns.size === 1) add(`SQL function call (${[...genericFns][0]})`, 15);
  return found;
}

/**
 * Structural SQL evidence in a payload. Empty when the text carries no SQL syntax.
 * Signals come from the single most incriminating tokenisation, never a mixture.
 */
export function analyseSqlStructure(raw: string): SqlSignal[] {
  if (!raw) return [];
  const s = (raw.length > MAX_LEN ? raw.slice(0, MAX_LEN) : raw).toLowerCase();
  // Nothing below can fire without one of these.
  if (!/[=()';"]|select|waitfor|order\s+by|group\s+by/.test(s)) return [];

  const views = [s];
  const sq = s.indexOf("'");
  if (sq !== -1 && sq + 1 < s.length) views.push(s.slice(sq + 1));
  const dq = s.indexOf('"');
  if (dq !== -1 && dq + 1 < s.length) views.push(s.slice(dq + 1));

  let best: Map<string, number> | null = null;
  let bestTotal = 0;
  for (const v of views) {
    const found = analyseTokens(tokenize(v));
    let total = 0;
    for (const w of found.values()) total += w;
    if (total > bestTotal) { best = found; bestTotal = total; }
  }
  if (!best) return [];
  return [...best.entries()].map(([label, weight]) => ({ label, weight })).sort((a, b) => b.weight - a.weight);
}
