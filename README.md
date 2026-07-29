<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/relintio-logo-dark.svg">
    <img src="./assets/relintio-logo-light.svg" alt="Relintio" width="260">
  </picture>

  <h1>Relintio Inspector</h1>

  <p>
    <a href="https://relintio.com/docs"><img alt="docs" src="https://img.shields.io/badge/docs-relintio.com-efd420"></a>
    <a href="./manifest.json"><img alt="manifest" src="https://img.shields.io/badge/manifest-v3-efd420"></a>
    <a href="./LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-efd420"></a>
  </p>

  <p><strong>A Chrome extension that answers two questions about the page in front of you.</strong></p>
</div>

---

Is this page protected by Relintio, and has a licence key reached the browser. The second question is the reason the extension exists. A licence key (`UP_LIVE_…`) is the HMAC key that signs challenge passports and outbound request signatures: one sitting in a frontend bundle is a WAF bypass for anyone who opens devtools, and it will not announce itself. This is not an SDK and not an npm package — `package.json` is `private` and there is nothing here to install into an application. It is a toolbar button that reads one page, once, when you ask it to. The entry point is `src/popup.js`, which injects `collectFromPage` into the active tab and renders what comes back.

## Install

Not yet on the Chrome Web Store — a listing is pending, and `STORE_LISTING.md` in this directory is the submission draft. Until then, load it unpacked:

1. Open `chrome://extensions`
2. Turn on **Developer mode**
3. **Load unpacked**, and choose this directory

There is no build step. The directory as it stands is the extension: `manifest.json`, three files in `src/`, four icons.

## What it looks for

Click the toolbar icon on any `http` or `https` page. Nothing runs before that click.

**Credentials.** Two patterns, in the page markup, every inline script, and every external bundle it can fetch.

| Pattern | Matches | Severity |
| --- | --- | --- |
| `UP_LIVE_` or `UP_TEST_` + 8 or more of `[A-Za-z0-9_-]` | A licence key | **critical** |
| `pk_live_` or `pk_test_` + 16 or more alphanumerics | A publishable key | info |

A publishable key is reported as expected, not as a finding. It is public by design, scoped to asking for a verdict, and belongs in frontend code — flagging it would teach people to dismiss the panel, and then the real key gets through. A test licence key is critical alongside the live one: it is still a key, and a test key in production usually means the live one is in a branch behaving the same way.

The length floors are what keep prose out of the results. `Set your UP_LIVE_ key in the environment` does not match, and there is a test that says so.

**Whether an agent is here**, from independent signals, because each one alone is wrong somewhere — a bundler renames the package away, a single-page app makes no verdict call until the visitor does something, a CDN strips headers.

| Signal | Evidence | Source |
| --- | --- | --- |
| Package | `@relintio/<name>` in a source, or a script URL containing `relintio` | Scripts and markup |
| Traffic | Calls to `/agent/decision`, `/agent/verify` or `/agent/log` | Resource Timing buffer |
| Passport | A `relintio_passport` cookie | `document.cookie` |
| Headers | Any `x-relintio*` response header | Not collected today — see below |

Calls to `/agent/verify` from a browser are escalated to critical on their own. That endpoint answers with the whole policy and is only ever called by an agent holding a licence key, so a browser reaching it means the key is in the browser even when the scan cannot find it in the source — assembled at runtime, decoded from base64, fetched from somewhere else.

## What it shows you

Findings are redacted. Twelve characters and a count — `UP_LIVE_a1b2…24 more` — which is enough to grep your own source for and not enough to use. A screenshot of this popup must not become the second place a key was published, and the test suite asserts the tail never appears anywhere in a finding, not only in the helper.

One key found in several places is one leak. The page markup and the inline script it contains are collected separately, so a key in an inline script is genuinely seen twice; the summary counts distinct keys, because "3 licence keys are readable" for one mistake is the kind of number that gets an extension uninstalled.

The panel never says a site is unprotected. A server-side agent enforces before anything reaches the browser and leaves nothing here to find, so the absence of every signal is reported as *nothing visible*. And it says what it could not read: a bundle served without CORS is named in a **What this scan could not see** section rather than counted as clean.

There is nothing to configure. No options page, no storage, no account, no state that survives the popup closing.

## Permissions

Two, and no host permissions at all. A security vendor's extension that reads every site you visit is a worse trade than the problem it solves.

| Permission | Why it is needed |
| --- | --- |
| `activeTab` | Grants access to the one tab whose toolbar icon you clicked, for that click only. It is what lets the extension read the page you are inspecting, and it expires — there is no way to reach a tab you have not opened the popup on. |
| `scripting` | Required by `chrome.scripting.executeScript`, which runs the one-shot collection function in that tab. It is what makes a content script on every page unnecessary. |

Nothing else is declared. No `host_permissions`, no `background` service worker, no `storage`, no `webRequest`, no `cookies`. The manifest sets `script-src 'self'; object-src 'none'` for extension pages, and every byte of code ships in the package — nothing is fetched or evaluated at runtime.

The extension makes no network requests of its own. The only fetches are for the page's own script URLs, issued from inside that page with `credentials: 'omit'`. Nothing you look at is sent anywhere, because there is nowhere for it to be sent.

`src/popup.js` builds its output with `createElement` and text nodes and never assigns page-derived content to `innerHTML`. Everything it displays — script URLs, header values, labels — is controlled by the page being inspected, and the popup runs with the extension's own origin and privileges.

## What this scan cannot see

**The headers signal cannot fire today.** `detectAgent` accepts a `headers` object and looks for `x-relintio*`, and there is a test for it, but `collectFromPage` never collects response headers and `popup.js` never passes any. The store listing describes four signals; three of them can reach the panel. Either wire the headers through or drop the claim from `STORE_LISTING.md` before submitting.

**The passport signal firing is itself a finding, and is not reported as one.** Cookies come from `document.cookie`, which excludes `HttpOnly` cookies, and every Relintio agent sets `relintio_passport` as `HttpOnly`. So on a correct install the signal never appears — and on an install where it does appear, the panel reports it as healthy evidence of protection rather than as the misconfiguration it is.

**A source over 2 MB is truncated silently.** `MAX_SOURCE_BYTES` is 2,000,000 per source and the excess is dropped with no note in the output — a key past that offset in a large bundle is missed, and the scan still reports clean. The 40-source cap is handled properly by comparison: it stops and says it stopped.

**That cap counts everything.** The page markup and every inline script occupy slots, and only the external-script branch checks the limit, so a page with dozens of inline scripts can exhaust the budget before the first bundle is fetched.

**Bundles are read from cache.** The fetch uses `cache: 'force-cache'`, so what is scanned is the copy the browser already holds. A key removed in a deploy the browser has not picked up will still be found, and one added in it may not be.

**Cross-origin bundles are unreadable.** A script served without CORS cannot be read by the page, and neither can this. It is reported, not counted as clean.

**Traffic evidence comes from the Resource Timing buffer**, so it covers what the document has already fetched since it loaded, not what it does next. A verdict call made after you open the popup is not in it; reload with the popup closed and look again.

**Some pages are off limits to every extension** — `chrome://` pages, the Web Store, and a few others. The popup says so rather than showing an empty result.

## Development

```bash
npm test
```

24 tests, no dependencies, `node --test`. `src/scan.js` holds the patterns, the redaction, the detection and the summary, and is deliberately pure — no `chrome.*`, no DOM — so all of it is testable in Node. That is where the whole test suite points, because it is the only part of this extension that can hurt someone: by missing a published key, by printing one, or by crying wolf over a publishable key until nobody reads the panel.

Reload from `chrome://extensions` after editing. There is no watcher and nothing to compile.

## Links

- [Documentation](https://relintio.com/docs)
- [API reference](https://relintio.com/docs/api-reference)
- [Licenses](https://relintio.com/licenses)
- [`STORE_LISTING.md`](./STORE_LISTING.md) — the pending Chrome Web Store submission, including the permission justifications above

Security reports go to **support@relintio.com**, not to a public issue.

## License

MIT. See [`LICENSE`](./LICENSE).
