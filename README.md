# BrandEveryVuln

A small synchronous website that gives a CVE a name and a logo. Heartbleed, Log4Shell, and the rest of the famous set keep the names they already had. Anything else is coined on the first request and filed on disk.

The server is blocking Rust: [`tiny_http`](https://crates.io/crates/tiny_http) for HTTP and [`ureq`](https://crates.io/crates/ureq) for outbound calls. There is no async runtime.

## Run

```bash
export OPENROUTER_API_KEY=sk-or-...   # required only to coin a new name
# export NVD_API_KEY=...               # optional; raises the NVD rate limit
export BIND=0.0.0.0:43123             # optional
# export PROJECT_ROOT=/opt/brandeveryvuln   # when the binary is not started from the project directory
cargo run
```

The binary stays `vulnmark` (`cargo run`, or `target/release/vulnmark` for the systemd unit). Then open http://127.0.0.1:43123. The repo pins a current stable toolchain in `rust-toolchain.toml`.

`.env`, `static/`, and the default `cache/` are resolved at runtime, not from the machine that compiled the binary. The search order is `PROJECT_ROOT` if set, the current working directory when it contains `Cargo.toml` or `static/`, then the executable's directory walked upward until `static/` is found, and only then the compile-time crate directory. `CACHE_DIR` still overrides the cache location on its own.

You can also put those variables in a `.env` file in the project root. The server reads it on startup and does not override variables that are already set. `.env` is gitignored. Never commit a key.

| Variable | Default | Purpose |
| --- | --- | --- |
| `OPENROUTER_API_KEY` | unset | Names and logos for CVEs that are not already filed. If it is missing or rejected, the desk still files an offline name and SVG |
| `NVD_API_KEY` | unset | Optional key for the NVD CVE API |
| `BIND` | `0.0.0.0:43123` | `host:port` the server listens on |
| `CACHE_DIR` | `cache` under the project root | Where dossiers are stored. A relative or absolute path overrides the default |
| `PROJECT_ROOT` | discovered at runtime | Directory that holds `static/` and `.env`. Set this when systemd's working directory is not the project |
| `BASE_DOMAIN` | unset | Bare domain, no scheme. When set, each dossier is also `https://cve-year-seq.$BASE_DOMAIN/` |

`cargo test` covers id parsing, NVD field selection, cache writes, and HTML escaping. It does not call NVD or OpenRouter.

## Routes

- `/` — the wall of famous names, a search box, a random button, and a few real CVEs that have no name on file
- `/cve/CVE-2026-0001` — one dossier: name, logo, tagline, and the NVD description, vendor, product, and CVSS. This path keeps working on the apex
- `https://cve-2026-0001.$BASE_DOMAIN/` and `https://2026-0001.$BASE_DOMAIN/` — the same dossier, when `BASE_DOMAIN` is set. The label is case-insensitive. The page's canonical link points at the `cve-…` host
- `/random` — redirects to a plausible recent id, and sometimes to one already on file. With `BASE_DOMAIN` set, the redirect (and the links on the wall and in search) use the subdomain URL. Without it, they stay on `/cve/<id>` so localhost still works
- `/lookup?id=CVE-...` — the form target. A bad id gets a plain error, not a stack trace

`www.$BASE_DOMAIN` redirects to the apex. Any other single label that is not a CVE id gets a short error and a link home. Hosts that are not under the base domain (a raw IP, `localhost`) are still served as the apex, so a local process keeps working. CSS, fonts, the favicon, and `/cve/<id>/logo` are served on every host, so a subdomain page can load them with root-relative URLs. A first visit on a subdomain goes through the same cache, lock, and offline fallback as a path visit.

## Deployment

Wildcard names need DNS and a certificate that covers them. Point the apex and a first-level wildcard at the machine:

```
brandeveryvuln.com.      A      <server-ip>
*.brandeveryvuln.com.    A      <server-ip>
```

A CNAME works for the wildcard too, if the DNS host allows `*.brandeveryvuln.com` to alias the apex. `www` is included in that wildcard.

Let's Encrypt HTTP-01 cannot issue a certificate for `*.brandeveryvuln.com`. Use one of:

- DNS-01 with Caddy or certbot (a DNS provider token, so the CA can read a TXT record).
- Cloudflare's proxy in front of the origin. The free plan's Universal SSL covers the apex and one level of wildcard (`*.brandeveryvuln.com`). Set SSL mode to Full (strict) and install an origin certificate, or Full if Caddy still terminates TLS itself.

Caddy in front of the binary, with the DNS module for a wildcard cert:

```
brandeveryvuln.com, www.brandeveryvuln.com, *.brandeveryvuln.com {
    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }
    reverse_proxy 127.0.0.1:43123
}
```

Run the desk on loopback and tell it the public name:

```
export BIND=127.0.0.1:43123
export BASE_DOMAIN=brandeveryvuln.com
export OPENROUTER_API_KEY=...
cargo run --release
```

Caddy forwards the original `Host` and sets `X-Forwarded-Proto`, which the desk uses when it writes `https://` links. Only the first label is a CVE (`cve-2021-44228.brandeveryvuln.com`). A name like `a.b.brandeveryvuln.com` is not served as a dossier.

CVE ids must look like `CVE-2021-44228`: a year from 1999 through 2099 and a sequence of four to seven digits. The sequence is kept as written, so `CVE-2026-0001` is filed at `cache/2026/0001/`.

## How a new name is made

1. `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-...` for the English description, CPE vendor and product, and CVSS. The score prefers v3.1, then v3.0, then v4.0, then v2. Without an NVD key the client stays under the public limit of about 5 requests per 30 seconds, and it backs off on 403 and 429.
2. OpenRouter chat completions, model `meta-llama/llama-3.1-8b-instruct` (Meta: Llama 3.1 8B Instruct), asked for JSON: `name`, `tagline`, `blurb`, `logo_prompt`. Junk, a reused famous name, an auth or credit error, a rate limit, or a missing key falls through to the offline wordlist.
3. OpenRouter image generation, `POST https://openrouter.ai/api/v1/images`, model `recraft/recraft-v4.1-flash-v2` (Recraft: Recraft V4.1 Flash V2), square. The bytes come back as base64 (or, if a URL is returned, they are downloaded). If that call fails, the desk draws an SVG itself.

The two fallbacks are independent. A good name with a failed image still keeps the name and stores an SVG. A failed name still tries the image model with the wordlist name. `branding.json` records `naming_source` and `logo_source` as `model` / `recraft` or `offline`. The page shows a small “Generated offline” line when either path was local.

Offline names come from `src/wordlist.txt`. A roll sometimes uses a keyword from the NVD product or description instead, then adds a suffix such as `2Shell`, `Bleed`, `pocalypse`, `Doom`, `-Gate`, or `Storm` (so a stem like Pickle can become Pickle2Shell). The SVG is a severity-colored mark with the name and a couple of those keywords. No emoji.

A dossier is filed once a name and a logo exist, including an offline pair. Two requests for the same id share one in-process lock and a lock file, so the work runs once. The result stays cached either way.

Famous dossiers carry `"prefilled": true` and a `.prefilled` marker. The server will not regenerate them, even if the JSON is damaged.

## Cache and git

```
cache/<year>/<sequence>/branding.json
cache/<year>/<sequence>/logo.png     # or svg, webp, jpg
```

`branding.json` holds the name, tagline, blurb, NVD fields, model ids, and a timestamp.

Generated folders are gitignored. Two exceptions are committed:

- the 15 prefilled famous CVEs
- `cache/2026/0001/`, the live generation of CVE-2026-0001, so the result is visible without an API key

A new id such as `cache/2025/12345/` stays untracked.

## The wall

| CVE | Name | Mark |
| --- | --- | --- |
| CVE-2014-0160 | Heartbleed | CC0, Leena Kurjenniska / Codenomicon, heartbleed.com |
| CVE-2014-6271 | Shellshock | CC0, rootworks, via Openclipart |
| CVE-2014-3566 | POODLE | monogram |
| CVE-2015-0235 | GHOST | monogram |
| CVE-2015-1538 | Stagefright | monogram |
| CVE-2016-0800 | DROWN | CC0, Sarah Madden, drownattack.com |
| CVE-2016-5195 | Dirty COW | CC0, dirtycow.ninja |
| CVE-2017-0144 | EternalBlue | monogram |
| CVE-2017-5753 | Spectre | CC0, Natascha Eibl, meltdownattack.com |
| CVE-2017-5754 | Meltdown | CC0, Natascha Eibl, meltdownattack.com |
| CVE-2017-13077 | KRACK | CC BY-SA, Mathy Vanhoef, krackattacks.com, unmodified |
| CVE-2019-0708 | BlueKeep | monogram |
| CVE-2020-1472 | Zerologon | monogram |
| CVE-2021-44228 | Log4Shell | monogram |
| CVE-2024-6387 | regreSSHion | monogram |

The Rust sources are MIT. Logo files keep the license named in their `branding.json`. The KRACK logo is CC BY-SA and is not covered by the MIT license.

Heartbleed, Dirty COW, DROWN, Spectre, Meltdown, and KRACK link to the sites that published them. GHOST links to the Qualys advisory, Log4Shell to the Apache Logging security page, and regreSSHion to the Qualys write-up.
