/**
 * What runs inside the page, and only when the user asks for it.
 *
 * Injected by `chrome.scripting.executeScript` on a click, under `activeTab`.
 * That is the whole permission model: no host permissions, no background
 * worker, no content script sitting on every page you visit. A security
 * vendor's extension that reads every site you open is a worse trade than the
 * problem it solves, and it is also the reason store reviews take weeks.
 *
 * This function is serialised and evaluated in the page, so it can close over
 * nothing. Everything it needs is inside it, and everything it returns has to
 * survive structured cloning.
 */
export async function collectFromPage() {
  const MAX_SOURCE_BYTES = 2_000_000;
  const MAX_SOURCES = 40;

  const sources = [];
  const errors = [];

  // The page markup with script bodies removed, because each inline script is
  // collected separately below. Without this, one key in one inline script is
  // found twice — once here and once there — and the panel reports two leaks
  // where there is one. What is left still matters: a key pasted into a
  // `data-` attribute, a meta tag, or a hidden input is invisible to a scan of
  // the scripts alone.
  sources.push({
    label: 'page markup',
    url: location.href,
    body: document.documentElement.outerHTML
      .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '<script></script>')
      .slice(0, MAX_SOURCE_BYTES),
  });

  const scripts = [...document.querySelectorAll('script')];

  for (const [index, script] of scripts.entries()) {
    if (!script.src) {
      if (script.textContent) {
        sources.push({
          label: `inline script #${index + 1}`,
          body: script.textContent.slice(0, MAX_SOURCE_BYTES),
        });
      }

      continue;
    }

    if (sources.length >= MAX_SOURCES) {
      // Said out loud rather than silently truncated: a scan that stopped
      // early and reported "clean" is worse than one that says it stopped.
      errors.push(`Stopped after ${MAX_SOURCES} scripts. Re-run on a page with fewer bundles, or check the rest by hand.`);
      break;
    }

    try {
      // Same-origin and CORS-permitted scripts only. A cross-origin bundle
      // the browser will not hand us is one we cannot read — reported rather
      // than counted as clean.
      const response = await fetch(script.src, { credentials: 'omit', cache: 'force-cache' });

      if (!response.ok) {
        errors.push(`Could not read ${script.src} (HTTP ${response.status}).`);
        continue;
      }

      const body = await response.text();

      sources.push({
        label: new URL(script.src, location.href).pathname.split('/').pop() || script.src,
        url: script.src,
        body: body.slice(0, MAX_SOURCE_BYTES),
      });
    } catch {
      errors.push(`Could not read ${script.src} — it is served without CORS, so this scan cannot see inside it.`);
    }
  }

  // Non-HttpOnly cookies only, which is the point: the passport cookie is set
  // HttpOnly by every agent, so seeing it here would itself be a finding.
  const cookies = document.cookie
    .split(';')
    .map((part) => part.split('=')[0].trim())
    .filter(Boolean)
    .map((name) => ({ name }));

  // Anything the page has already fetched, from the Resource Timing buffer.
  // No network permission needed, and it covers the verdict calls an agent
  // makes on load.
  const requests = performance
    .getEntriesByType('resource')
    .map((entry) => ({ url: entry.name, duration: Math.round(entry.duration) }))
    .filter((entry) => /\/agent\/(decision|verify|log)\b/.test(entry.url));

  return { sources, errors, cookies, requests, url: location.href };
}
