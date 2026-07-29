/**
 * What the extension actually looks for.
 *
 * Kept as pure functions with no `chrome.*` and no DOM, so it can be tested in
 * Node — which matters more here than usual. This is the only part of the
 * extension that can be wrong in a way that hurts someone: a scanner that
 * misses a published licence key tells a developer their site is fine when it
 * is not, and one that prints the key it found has published it a second time.
 *
 * Run: node --test test/scan.test.mjs
 */

/**
 * A licence key.
 *
 * `UP_LIVE_…` is the HMAC key that signs challenge passports and request
 * signatures. Anyone holding it can mint themselves a pass through the WAF it
 * belongs to, so one appearing anywhere a browser can read it is a compromise
 * of that customer's protection, not a configuration smell.
 *
 * `UP_TEST_` is the same shape against a test licence. Still a key, still
 * should not be in a bundle, and a test key in production usually means the
 * live one is in a branch somewhere.
 */
export const LICENCE_KEY = /\bUP_(?:LIVE|TEST)_[A-Za-z0-9_-]{8,}/g;

/**
 * A publishable key.
 *
 * `pk_live_` + 40 hex. Public by design, scoped to `decision:read`, and
 * expected in frontend code — finding one is how we know an SDK is installed
 * rather than a problem to report.
 */
export const PUBLISHABLE_KEY = /\bpk_(?:live|test)_[A-Za-z0-9]{16,}/g;

export const SEVERITY_CRITICAL = 'critical';
export const SEVERITY_INFO = 'info';

/**
 * How much of a key is ever shown.
 *
 * Enough to find it in your own source, not enough to use. The extension must
 * not become the second place a key was published — a screenshot of this popup
 * would otherwise carry the whole credential.
 */
const VISIBLE_PREFIX = 12;

export function redact(key) {
  const value = String(key);

  return value.length <= VISIBLE_PREFIX
    ? value
    : `${value.slice(0, VISIBLE_PREFIX)}…${value.length - VISIBLE_PREFIX} more`;
}

/**
 * Scan one source for credentials.
 *
 * @param {{ label: string, url?: string, body: string }} source
 * @returns {Array<{severity: string, kind: string, redacted: string, label: string, url?: string, line: number}>}
 */
export function scanSource(source) {
  const body = String(source?.body ?? '');

  if (body === '') {
    return [];
  }

  const findings = [];

  for (const [kind, pattern, severity] of [
    ['licence_key', LICENCE_KEY, SEVERITY_CRITICAL],
    ['publishable_key', PUBLISHABLE_KEY, SEVERITY_INFO],
  ]) {
    // Fresh regex per pass: these are global, and a shared `lastIndex` between
    // sources silently skips the beginning of every source after the first.
    const expression = new RegExp(pattern.source, pattern.flags);
    let match;

    while ((match = expression.exec(body)) !== null) {
      findings.push({
        severity,
        kind,
        redacted: redact(match[0]),
        label: source.label,
        url: source.url,
        line: lineOf(body, match.index),
      });

      // A zero-length match would loop forever. The patterns cannot produce
      // one today; this is the guard for the day one is edited.
      if (match[0].length === 0) {
        expression.lastIndex += 1;
      }
    }
  }

  return findings;
}

/** Scan several sources, deduplicated by key and location. */
export function scanAll(sources) {
  const seen = new Set();
  const findings = [];

  for (const source of Array.isArray(sources) ? sources : []) {
    for (const finding of scanSource(source)) {
      // The same bundle is often loaded twice — once as a `<script src>` and
      // again from the HTML that references it. One key reported twice reads
      // as two leaks.
      const key = `${finding.kind}:${finding.redacted}:${finding.url ?? finding.label}:${finding.line}`;

      if (seen.has(key)) {
        continue;
      }

      seen.add(key);
      findings.push(finding);
    }
  }

  return findings.sort((a, b) => severityRank(a) - severityRank(b));
}

function severityRank(finding) {
  return finding.severity === SEVERITY_CRITICAL ? 0 : 1;
}

function lineOf(body, index) {
  let line = 1;

  for (let i = 0; i < index; i += 1) {
    if (body.charCodeAt(i) === 10) {
      line += 1;
    }
  }

  return line;
}

/**
 * Which Relintio SDK, if any, this page is running.
 *
 * Four independent signals, because each one alone is wrong somewhere. A
 * bundler renames the package, so the script URL disappears. A single-page app
 * makes no verdict call until the visitor does something. Response headers are
 * stripped by some CDNs. And the passport cookie only exists after a challenge
 * has been solved.
 *
 * @param {{ sources?: Array<{label: string, url?: string, body: string}>,
 *           requests?: Array<{url: string}>,
 *           headers?: Record<string, string>,
 *           cookies?: Array<{name: string}> }} evidence
 */
export function detectAgent(evidence = {}) {
  const signals = [];
  const sources = evidence.sources ?? [];
  const requests = evidence.requests ?? [];
  const headers = normaliseHeaders(evidence.headers);
  const cookies = evidence.cookies ?? [];

  const packageNames = new Set();

  for (const source of sources) {
    for (const match of String(source.body ?? '').matchAll(/@relintio\/([a-z-]+)/g)) {
      packageNames.add(`@relintio/${match[1]}`);
    }

    if (source.url && /relintio/i.test(source.url)) {
      packageNames.add(source.url);
    }
  }

  if (packageNames.size > 0) {
    signals.push({
      signal: 'package',
      detail: [...packageNames].sort().join(', '),
    });
  }

  const endpoints = new Set();

  for (const request of requests) {
    const url = String(request?.url ?? '');

    if (/\/agent\/decision\b/.test(url)) {
      endpoints.add('/agent/decision');
    }

    if (/\/agent\/verify\b/.test(url)) {
      endpoints.add('/agent/verify');
    }

    if (/\/agent\/log\b/.test(url)) {
      endpoints.add('/agent/log');
    }
  }

  if (endpoints.size > 0) {
    signals.push({ signal: 'traffic', detail: [...endpoints].sort().join(', ') });
  }

  const headerNames = Object.keys(headers).filter((name) => name.startsWith('x-relintio'));

  if (headerNames.length > 0) {
    signals.push({
      signal: 'headers',
      detail: headerNames.map((name) => `${name}: ${headers[name]}`).join('; '),
    });
  }

  if (cookies.some((cookie) => cookie?.name === 'relintio_passport')) {
    signals.push({ signal: 'passport', detail: 'This browser holds a solved challenge passport.' });
  }

  return {
    protected: signals.length > 0,
    signals,
    // `/agent/verify` is only ever called by an agent holding a licence key,
    // which is a server. Seeing it from a browser means the licence key is in
    // the browser — the same incident the scanner looks for, arriving by a
    // different route.
    verifyFromBrowser: endpoints.has('/agent/verify'),
  };
}

function normaliseHeaders(headers) {
  const out = {};

  for (const [name, value] of Object.entries(headers ?? {})) {
    out[String(name).toLowerCase()] = String(value);
  }

  return out;
}

/**
 * Turn findings into the one sentence the popup leads with.
 *
 * A leaked licence key outranks everything, including "no agent found" — a
 * page with a published key and no working agent is in the worst state
 * available, and reporting the missing agent first would bury it.
 */
export function summarise(findings, detection) {
  // Counted by distinct key, not by occurrence. One key that appears in the
  // page markup and again in the bundle it was inlined into is one leak, and
  // "3 licence keys are readable" for a single mistake is the kind of number
  // that gets an extension uninstalled.
  const leaked = new Set(
    findings
      .filter((f) => f.severity === SEVERITY_CRITICAL)
      .map((f) => f.redacted),
  );

  if (leaked.size > 0) {
    return {
      status: 'critical',
      headline: leaked.size === 1
        ? 'A licence key is readable in this page'
        : `${leaked.size} licence keys are readable in this page`,
      detail: 'A licence key signs challenge passports and request signatures. Anyone who opens devtools on this page can mint themselves a pass through your WAF. Rotate it in Dashboard → API keys, then replace it in your frontend with a publishable key (pk_live_…).',
    };
  }

  if (detection?.verifyFromBrowser) {
    return {
      status: 'critical',
      headline: 'This page is calling /agent/verify from the browser',
      detail: 'That endpoint answers with the whole policy and is only ever called by an agent holding a licence key. A browser reaching it means the key is in the browser, even though this scan did not find it in the source — check for one assembled at runtime.',
    };
  }

  if (!detection?.protected) {
    return {
      status: 'unknown',
      headline: 'No Relintio agent detected on this page',
      detail: 'That does not mean the site is unprotected: a server-side agent enforces before anything reaches the browser and leaves nothing here to find. This panel can only see what the browser can.',
    };
  }

  const publishable = findings.filter((f) => f.kind === 'publishable_key');

  return {
    status: 'ok',
    headline: 'Relintio is running on this page',
    detail: publishable.length > 0
      ? 'A publishable key is present, which is correct — it is public by design and can only ask for a verdict.'
      : 'No credential is exposed in the page source.',
  };
}
