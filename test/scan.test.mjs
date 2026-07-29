/**
 * The scanner is the only part of this extension that can hurt someone.
 *
 * A scan that misses a published licence key tells a developer their site is
 * fine when anyone with devtools can walk through their WAF. A scan that
 * prints the key it found has published it a second time, in a screenshot. And
 * a scan that cries wolf over a publishable key — which is public by design —
 * teaches people to ignore it, which is how the real one gets through.
 *
 * Run: node --test test/scan.test.mjs
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

const { scanSource, scanAll, redact, detectAgent, summarise, LICENCE_KEY } = await import('../src/scan.js');

const LICENCE = 'UP_LIVE_' + 'a1b2c3d4'.repeat(4);
const PUBLISHABLE = 'pk_live_' + 'f0'.repeat(20);

const source = (body, label = 'bundle.js', url = 'https://shop.example.com/bundle.js') => ({
  label,
  url,
  body,
});

describe('finding a leaked licence key', () => {
  it('finds one in a bundle', () => {
    const findings = scanSource(source(`const config = { licenseKey: '${LICENCE}' };`));

    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'critical');
    assert.equal(findings[0].kind, 'licence_key');
  });

  it('finds a test key too', () => {
    // A test key in a bundle is still a key, and usually means the live one is
    // in a branch somewhere behaving the same way.
    const findings = scanSource(source(`key = "UP_TEST_${'9'.repeat(20)}"`));

    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'critical');
  });

  it('reports the line it is on', () => {
    const findings = scanSource(source(`line one\nline two\nconst k = '${LICENCE}';`));

    assert.equal(findings[0].line, 3);
  });

  it('finds every occurrence rather than only the first', () => {
    const findings = scanSource(source(`a='${LICENCE}';\nb='UP_LIVE_${'z'.repeat(16)}';`));

    assert.equal(findings.filter((f) => f.severity === 'critical').length, 2);
  });

  it('keeps scanning past the first source', () => {
    // A shared `lastIndex` on a global regex silently skips the beginning of
    // every source after the first, so the leak in a second bundle disappears
    // — with the scan still reporting success.
    const findings = scanAll([
      source('nothing here at all, but quite a long line to move lastIndex along'),
      source(`const k = '${LICENCE}';`, 'second.js', 'https://shop.example.com/second.js'),
    ]);

    assert.equal(findings.length, 1);
    assert.equal(findings[0].url, 'https://shop.example.com/second.js');
  });

  it('is not thrown off by a caller who used the exported pattern first', () => {
    // `LICENCE_KEY` is exported and global, so its `lastIndex` is shared
    // mutable state. Anyone calling `.test()` on it — the popup rendering a
    // hint, a contributor adding a check — leaves it pointing into the middle
    // of their string, and a scanner that reuses the object then starts there
    // and reports the page clean.
    LICENCE_KEY.test(`padding padding padding ${LICENCE} padding`);
    assert.notEqual(LICENCE_KEY.lastIndex, 0, 'the hazard this guards against must be real');

    const findings = scanSource(source(`const k = '${LICENCE}';`));

    assert.equal(findings.length, 1, 'the scan must not inherit someone else’s cursor');

    LICENCE_KEY.lastIndex = 0;
  });

  it('reports one key once, however many sources carry it', () => {
    const findings = scanAll([source(`k='${LICENCE}'`), source(`k='${LICENCE}'`)]);

    assert.equal(findings.length, 1);
  });

  it('puts the critical findings first', () => {
    const findings = scanAll([source(`pk='${PUBLISHABLE}'; lk='${LICENCE}';`)]);

    assert.equal(findings[0].severity, 'critical');
    assert.equal(findings[1].severity, 'info');
  });
});

describe('never publishing the key a second time', () => {
  it('shows enough to find it and not enough to use it', () => {
    const shown = redact(LICENCE);

    assert.ok(shown.startsWith('UP_LIVE_a1b2'), 'the prefix is what makes it findable');
    assert.ok(!shown.includes(LICENCE.slice(16)), 'the rest must not appear');
    assert.ok(shown.length < LICENCE.length, 'a redaction that is longer is not a redaction');
  });

  it('redacts in the findings, not only in the helper', () => {
    const findings = scanSource(source(`k='${LICENCE}'`));

    assert.ok(!JSON.stringify(findings).includes(LICENCE));
  });
});

describe('not crying wolf', () => {
  it('treats a publishable key as expected rather than as a leak', () => {
    // This is the one that decides whether anyone trusts the extension. A
    // publishable key is public by design; flagging it teaches people to
    // dismiss the panel, and then the real key gets through.
    const findings = scanSource(source(`publishableKey: '${PUBLISHABLE}'`));

    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'info');
    assert.equal(findings[0].kind, 'publishable_key');
  });

  it('does not match prose that merely mentions the prefix', () => {
    assert.deepEqual(scanSource(source('Set your UP_LIVE_ key in the environment.')), []);
    assert.deepEqual(scanSource(source('// pk_live_ keys are safe to publish')), []);
  });

  it('finds nothing in an empty or missing source', () => {
    assert.deepEqual(scanSource(source('')), []);
    assert.deepEqual(scanSource({ label: 'x' }), []);
    assert.deepEqual(scanAll(null), []);
    assert.deepEqual(scanAll(undefined), []);
  });
});

describe('working out whether an agent is here', () => {
  it('recognises the package in a bundle', () => {
    const result = detectAgent({ sources: [source("import { relintio } from '@relintio/vue-agent';")] });

    assert.equal(result.protected, true);
    assert.equal(result.signals[0].detail, '@relintio/vue-agent');
  });

  it('recognises the traffic when the bundle is minified past recognition', () => {
    // A bundler renames the package away, so the source signal disappears.
    const result = detectAgent({
      requests: [{ url: 'https://api.relintio.com/v1/agent/decision' }],
    });

    assert.equal(result.protected, true);
    assert.equal(result.signals[0].signal, 'traffic');
  });

  it('recognises the response headers', () => {
    const result = detectAgent({ headers: { 'X-Relintio-Action': 'allow' } });

    assert.equal(result.protected, true);
  });

  it('recognises a solved challenge', () => {
    const result = detectAgent({ cookies: [{ name: 'relintio_passport' }] });

    assert.equal(result.protected, true);
    assert.equal(result.signals[0].signal, 'passport');
  });

  it('says nothing rather than guessing when there is no signal at all', () => {
    const result = detectAgent({ sources: [source('const x = 1;')] });

    assert.equal(result.protected, false);
    assert.deepEqual(result.signals, []);
  });

  it('flags a browser calling the endpoint only a server should', () => {
    // `/agent/verify` answers with the whole policy and is only ever called by
    // an agent holding a licence key. A browser reaching it means the key is in
    // the browser, even when the scan cannot find it — assembled at runtime,
    // fetched from an endpoint, decoded from base64.
    const result = detectAgent({ requests: [{ url: 'https://api.relintio.com/v1/agent/verify' }] });

    assert.equal(result.verifyFromBrowser, true);
  });
});

describe('what the panel leads with', () => {
  it('leads with a leaked key over everything else', () => {
    // Including over "no agent found". A page with a published key and no
    // working agent is in the worst state available, and reporting the missing
    // agent first buries the incident.
    const summary = summarise(scanAll([source(`k='${LICENCE}'`)]), { protected: false });

    assert.equal(summary.status, 'critical');
    assert.match(summary.headline, /licence key is readable/);
    assert.match(summary.detail, /Rotate it/);
  });

  it('counts them when there is more than one', () => {
    const summary = summarise(
      scanAll([source(`a='${LICENCE}'; b='UP_LIVE_${'z'.repeat(16)}';`)]),
      { protected: true },
    );

    assert.match(summary.headline, /^2 licence keys/);
  });

  it('counts one key found in two places as one leak', () => {
    // The page markup and the inline script it contains are collected
    // separately, so a key in an inline script is genuinely seen twice. "2
    // licence keys are readable" for one mistake is the kind of number that
    // gets an extension uninstalled — and it makes the real count useless.
    const summary = summarise(
      scanAll([
        source(`k='${LICENCE}'`, 'page markup', 'https://shop.example.com/'),
        source(`k='${LICENCE}'`, 'inline script #1'),
      ]),
      { protected: true },
    );

    assert.match(summary.headline, /^A licence key is readable/);
  });

  it('does not claim a site is unprotected when it cannot tell', () => {
    // A server-side agent enforces before anything reaches the browser and
    // leaves nothing here to find. Saying "unprotected" would be wrong and
    // would be the sentence people screenshot.
    const summary = summarise([], { protected: false });

    assert.equal(summary.status, 'unknown');
    assert.match(summary.detail, /does not mean the site is unprotected/);
  });

  it('reports a publishable key as correct rather than as a finding', () => {
    const summary = summarise(scanAll([source(`k='${PUBLISHABLE}'`)]), { protected: true });

    assert.equal(summary.status, 'ok');
    assert.match(summary.detail, /which is correct/);
  });
});
