import { collectFromPage } from './collect.js';
import { detectAgent, scanAll, summarise } from './scan.js';

const output = document.getElementById('output');
const host = document.getElementById('host');

/**
 * Everything rendered here goes through `text()` or is built with
 * `createElement`. No `innerHTML` with page-derived content, ever: the popup
 * displays script URLs and header values that a hostile page controls, and an
 * extension popup runs with the extension's own origin and privileges.
 */
function text(value) {
  return document.createTextNode(String(value));
}

function element(tag, className, child) {
  const node = document.createElement(tag);

  if (className) {
    node.className = className;
  }

  if (child !== undefined) {
    node.appendChild(typeof child === 'string' ? text(child) : child);
  }

  return node;
}

function renderSummary(summary) {
  const wrapper = element('div', 'summary');
  const badge = element('div', `badge status-${summary.status}`);

  badge.appendChild(element('span', 'dot'));
  badge.appendChild(text({
    critical: 'Action needed',
    ok: 'Protected',
    unknown: 'Nothing visible',
  }[summary.status] ?? summary.status));

  wrapper.appendChild(badge);
  wrapper.appendChild(element('h1', null, summary.headline));
  wrapper.appendChild(element('p', null, summary.detail));

  return wrapper;
}

function renderFindings(findings) {
  const critical = findings.filter((f) => f.severity === 'critical');

  if (critical.length === 0) {
    return null;
  }

  const section = element('section');
  section.appendChild(element('h2', null, 'Exposed credentials'));

  for (const finding of critical) {
    const row = element('div', 'row critical');
    const body = element('div', 'body');

    body.appendChild(element('code', null, finding.redacted));
    body.appendChild(element('span', 'where', `${finding.label} · line ${finding.line}`));
    row.appendChild(body);
    section.appendChild(row);
  }

  return section;
}

function renderDetection(detection) {
  if (detection.signals.length === 0) {
    return null;
  }

  const section = element('section');
  section.appendChild(element('h2', null, 'How we can tell'));

  const labels = {
    package: 'Package in the bundle',
    traffic: 'Calls to the platform',
    headers: 'Response headers',
    passport: 'Challenge passport',
  };

  for (const signal of detection.signals) {
    const line = element('div', 'signal');
    line.appendChild(element('strong', null, `${labels[signal.signal] ?? signal.signal}: `));
    line.appendChild(text(signal.detail));
    section.appendChild(line);
  }

  return section;
}

function renderGaps(errors) {
  if (errors.length === 0) {
    return null;
  }

  const section = element('section');

  // Named rather than swallowed. A scan that skipped a bundle and then said
  // "clean" is the failure this whole extension exists to prevent, applied to
  // itself.
  section.appendChild(element('h2', null, 'What this scan could not see'));

  for (const error of errors) {
    section.appendChild(element('div', 'note', error));
  }

  return section;
}

async function run() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab?.id || !/^https?:/.test(tab.url ?? '')) {
    output.replaceChildren(element('div', 'empty', 'Open a web page and try again — there is nothing to inspect here.'));

    return;
  }

  try {
    host.appendChild(text(new URL(tab.url).host));
  } catch {
    // A URL we cannot parse is a URL we do not print.
  }

  let collected;

  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: collectFromPage,
    });

    collected = result?.result;
  } catch (error) {
    output.replaceChildren(element('div', 'empty',
      'Chrome would not let this run on the page — extension pages, the Web Store and a few others are off limits to every extension.'));

    return;
  }

  if (!collected) {
    output.replaceChildren(element('div', 'empty', 'The page returned nothing to inspect.'));

    return;
  }

  const findings = scanAll(collected.sources);
  const detection = detectAgent({
    sources: collected.sources,
    requests: collected.requests,
    cookies: collected.cookies,
  });

  const nodes = [
    renderSummary(summarise(findings, detection)),
    renderFindings(findings),
    renderDetection(detection),
    renderGaps(collected.errors ?? []),
  ].filter(Boolean);

  output.replaceChildren(...nodes);
}

run();
