# Relintio Inspector

A Chrome extension that answers two questions about the page you are looking
at: **is it protected by Relintio**, and **has a licence key reached the
browser**.

The second one is why this exists. A licence key (`UP_LIVE_…`) is the HMAC key
that signs challenge passports and request signatures — anyone holding it can
mint themselves a pass through that site's WAF. Every SDK we ship refuses to
start on one in the browser, `InstallRecipeService` throws rather than render
one into a frontend walkthrough, and the docs say so on every page. This is the
last line: the one that checks what actually shipped.

## Install

Not yet on the Chrome Web Store. To run it now:

1. Open `chrome://extensions`
2. Turn on **Developer mode**
3. **Load unpacked**, and choose this directory

## What it does

Click the toolbar icon on any page. It reads that page once and shows:

- **Exposed credentials.** Any `UP_LIVE_` or `UP_TEST_` key in the page markup,
  an inline script, or a bundle it can fetch. Shown redacted — the first twelve
  characters, enough to find it in your own source and not enough to use.
- **Whether an agent is here**, from four independent signals: the package name
  in a bundle, calls to `/agent/decision`, `X-Relintio-*` response headers, and
  the challenge passport cookie. Any one of them can be absent on a working
  install, so it looks for all four.
- **What it could not see.** A bundle served without CORS is a bundle this
  cannot read, and it says so rather than counting it as clean.

A publishable key (`pk_live_…`) is reported as expected, not as a finding. It
is public by design and can do exactly one thing: ask for a verdict. An
extension that flags it teaches people to dismiss the panel, and then the real
key gets through.

## What it does not do

- **No background monitoring.** There is no service worker and no content
  script. Nothing runs until you click the icon, on the tab you clicked it on.
- **No host permissions.** `activeTab` and `scripting`, which is the smallest
  set that can do this at all. It cannot read a page you have not opened it on.
- **No network.** Nothing is sent anywhere. The scan happens in your browser
  and the result is thrown away when the popup closes.

A security vendor's extension that reads every site you visit is a worse trade
than the problem it solves.

## Reporting "unprotected"

It does not. A server-side agent enforces before anything reaches the browser
and leaves nothing here to find, so the absence of a signal is reported as
*nothing visible*, never as *unprotected*. This panel can only see what the
browser can see.

## Development

```bash
npm test
```

`src/scan.js` holds the detection and the redaction, and is pure — no
`chrome.*`, no DOM — so it is tested in Node. That is deliberate: it is the
only part of this extension that can hurt someone, either by missing a
published key or by printing one.

## Licence

MIT. See [LICENSE](LICENSE).
