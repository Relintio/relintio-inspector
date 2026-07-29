# Chrome Web Store listing

Everything the submission form asks for, written out so it can be reviewed
before it is pasted. Nothing here is a placeholder.

## Item name

Relintio Inspector

## Summary (132 characters max)

> See whether a page is protected by Relintio, and catch a licence key that reached the browser before someone else does.

118 characters.

## Category

Developer Tools

## Language

English (United Kingdom)

## Description

> **Two questions, answered on the page you are looking at.**
>
> **Has a licence key reached the browser?** A Relintio licence key signs
> challenge passports and request signatures. One in a frontend bundle is a
> pass through that site's firewall for anyone who opens devtools. Relintio
> Inspector scans the page markup, every inline script and every bundle it can
> read, and shows you the key redacted — enough to find it in your source, not
> enough to use.
>
> **Is an agent running here?** It looks for four independent signals: the SDK
> package name in a bundle, calls to the Relintio decision endpoint,
> `X-Relintio` response headers, and the challenge passport cookie. Any one of
> them can be missing on a perfectly healthy install, so it checks all four and
> tells you which ones it found.
>
> It also tells you what it could not see. A bundle served without CORS is a
> bundle this cannot read, and it says so rather than reporting the page clean.
>
> **What it does not do**
>
> There is no background process and no content script. Nothing runs until you
> click the icon, and then only on that tab. It asks for `activeTab` and
> `scripting` — the smallest permissions that can do this at all — and it has
> no network access of its own. Nothing you look at is sent anywhere.
>
> It will never tell you a site is unprotected. A server-side agent enforces
> before anything reaches the browser and leaves nothing in the page to find,
> so the absence of a signal is reported as "nothing visible".
>
> **Who it is for**
>
> Developers integrating a Relintio SDK, and anyone auditing a site that uses
> one. Relintio is a runtime application security platform with SDKs for React,
> Vue, Svelte, Angular, Expo, PHP, Node.js, Python, Go, Ruby, C#, Java, Rust,
> Zig, Express, Nuxt, WordPress, Shopify, Vercel, Supabase and Firebase.
>
> Documentation: https://relintio.com/docs

## Justification for each permission

The store asks for these in a free-text field. Answer them exactly.

| Permission | Why it is needed |
| --- | --- |
| `activeTab` | The extension reads the page the user clicked the icon on, to scan its scripts for an exposed credential. It is granted per click and expires; the extension cannot read any tab the user has not opened it on. |
| `scripting` | Required to run the one-shot collection function in the page the user clicked on. There is no content script and no persistent injection. |

**Remote code:** none. All code is in the package; nothing is fetched or
evaluated at runtime.

**Data use:** the extension collects nothing and transmits nothing. There is no
analytics, no server, and no storage. Declare "does not collect or use user
data" and check all three certification boxes.

## Single purpose statement

> Inspect a web page for Relintio protection and for Relintio credentials that
> should not be present in browser-visible code.

## Screenshots required

1280×800 or 640×400, at least one, at most five. Take these against a real
page:

1. A page with a leaked licence key — the "Action needed" state.
2. A protected page — the "Protected" state with all four signals.
3. A page where a bundle could not be read — the "What this scan could not see"
   section.

## Store assets

| Asset | Size | Source |
| --- | --- | --- |
| Item icon | 128×128 | `icons/icon128.png` |
| Small promo tile | 440×280 | Needs producing — the mark on `#0a0a0b` with the product name. |
| Marquee promo tile | 1400×560 | Optional. Only shown to featured items. |

## Before submitting

- [ ] A privacy policy URL that covers this extension. `https://relintio.com/legal/privacy` already exists; confirm it says the extension collects nothing, or add a section.
- [ ] The `homepage_url` in `manifest.json` resolves.
- [ ] A publisher account verified against the `relintio.com` domain, so the listing shows the domain rather than a bare Google account. This is what makes the backlink worth having.
- [ ] The 5 USD one-time developer registration fee has been paid on the publishing account.
- [ ] `npm test` passes.

## About the backlink

A Chrome Web Store listing carries a `nofollow` link, so it passes no direct
PageRank. What it does is register the product on a high-authority domain
Google crawls constantly, which helps entity association and brand search — and
the listing itself ranks for "relintio" queries. Treat it as presence rather
than as link equity, and make the listing good on its own terms.
