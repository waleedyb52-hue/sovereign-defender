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
    '/items?where=color:red&limit=10', '/files/all_users/report.php?dir=http://10.0.0.5:8080/x', 'SELECT', 'select', 'where', "it's"
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
  it('stays fast on large adversarial input', () => {
    const inputs = [
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
      expect(performance.now() - t0).toBeLessThan(250);
    }
  });

  it('returns nothing for text with no SQL syntax characters', () => {
    expect(analyseSqlStructure('hello world this is plain text')).toEqual([]);
    expect(analyseSqlStructure('')).toEqual([]);
  });
});
