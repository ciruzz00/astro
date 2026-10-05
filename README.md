# astro

A threat intelligence search engine. One query, every source: hashes, IPs,
domains, URLs, CVEs, MITRE ATT&CK IDs, MAC addresses and threat names are
detected automatically and looked up across many intelligence feeds at once.

Built for incident response, threat hunting and CTF/DFIR challenges
(Hack The Box Sherlocks, TryHackMe).

> **Status:** early development. The CLI, the web interface, the REST API, cases
> and all the sources below work; TUI and PDF reports are on the roadmap.

## Features

- **Automatic detection** of MD5/SHA1/SHA256/SHA512, IPv4/IPv6, domains, URLs,
  emails, CVEs, ATT&CK IDs (`T1059.001`, `TA0002`, `G0032`, `S0154`, `M1036`,
  `C0022`), MAC addresses and free-text names (`"Lazarus Group"`).
- **Defanged input** accepted: `hxxps://evil[.]com`, `1.2.3[.]4`, `user[@]evil[.]com`.
- **IOC extraction** from logs, reports and emails, with de-duplication.
- **Offline datasets:** MITRE ATT&CK (enterprise, mobile, ICS), CISA KEV and
  the IEEE MAC registry, searchable without network access.
- **Parallel lookups** with per-source timeouts, rate limits and a local cache.
- **Cases** to collect indicators, results, notes and tags under a TLP marking,
  resume them later and export them as Markdown, JSON, STIX 2.1 or an ATT&CK
  Navigator layer.
- **JSON output** for scripting.

## Sources

| Source | Indicators | API key | Network |
|---|---|---|---|
| MITRE ATT&CK | ATT&CK IDs, group/software/campaign names | no | offline |
| VirusTotal | hash, IP, domain, URL | required | online |
| MalwareBazaar (abuse.ch) | MD5, SHA1, SHA256 | required | online |
| ThreatFox (abuse.ch) | hash, IP, domain, URL | required | online |
| URLhaus (abuse.ch) | URL, domain, IP, MD5/SHA256 payloads | required | online |
| AbuseIPDB | IP | required | online |
| AlienVault OTX | hash, IP, domain, URL, CVE | required | online |
| GreyNoise Community | IPv4 | optional | online |
| Shodan (InternetDB without a key) | IP | optional | online |
| NVD | CVE | optional | online |
| CISA KEV | CVE | no | offline |
| FIRST EPSS | CVE | no | online |
| IEEE OUI | MAC address | no | offline |

`astro providers` shows which sources are enabled with your keys. Sources that
require a key are skipped until it is set.

### OPSEC

Online sources receive the indicator you search, and some (like VirusTotal)
share lookups with their community. For sensitive indicators, such as internal
hostnames or unreleased samples, use `--offline` (offline datasets only) or
pick sources with `--only`.

## Install

Download the archive for your OS from the
[releases page](https://github.com/ciruzz00/astro/releases), verify it and
extract the `astro` binary:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify astro_<version>_<date>_<os>_<arch>.tar.gz --repo ciruzz00/astro
```

## Usage

```sh
astro sync                                   # download the offline datasets
astro search CVE-2021-44228                  # NVD + CISA KEV + EPSS
astro search T1059.001 "Lazarus Group"       # MITRE ATT&CK
astro search 00:50:56:aa:bb:cc               # MAC vendor, VM detection
astro search --file incident.log             # search every IOC in a file
astro extract --defang report.txt            # extract IOCs without searching
astro search --json 8.8.8.8 | jq .
astro search --offline 10.0.0.5              # nothing leaves this machine
astro search --only virustotal,malwarebazaar 44d88612fea8a8f36de82e1278abb02f
astro providers                              # enabled sources and missing keys
```

## Cases

```sh
astro case new brutus --title "HTB Sherlock: Brutus" --tlp green --tag htb
astro case add brutus -f auth.log --search          # extract, add and search IOCs
astro search --case brutus "Lazarus Group"          # save any search into a case
astro case note brutus "Initial access via SSH brute force"
astro case show brutus
astro case export brutus --format md -o brutus      # md, json, stix, navigator
astro case list --all
```

Cases keep the latest result of each indicator, so they can be resumed and
re-searched later (`astro case search brutus --all`). Exports are marked with the
case TLP; Markdown reports defang indicators and escape provider data, STIX
bundles use the OASIS TLP 2.0 markings, and Navigator layers highlight the case
techniques plus those referenced by threat intel on its indicators.

## Web interface

```sh
astro token create web    # prints a token once: it is your password for the UI
astro serve               # open http://127.0.0.1:8080 and sign in with the token
```

Everything the CLI does is available in the browser: search (one indicator per
line, extraction from pasted text or uploaded files, source selection, offline
mode), IOC extraction with bulk actions, cases (create, add, search, notes, tags,
edit, close, delete, export), dataset sync, source status and API token
management.

The interface is rendered on the server and works without JavaScript; htmx is
vendored (integrity-checked) for faster navigation. Sessions use HttpOnly,
SameSite=Strict cookies, cross-origin form posts are rejected, and a strict
Content-Security-Policy forbids inline scripts. Provider data is always escaped.
Revoking a token signs out its sessions. Use `astro serve --no-web` to serve the
API only.

## REST API

```sh
astro token create soar          # prints the token once: store it safely
astro serve                      # http://127.0.0.1:8080, localhost only
```

| Endpoint | Description |
|---|---|
| `GET /api/v1/health` | liveness (no token) |
| `GET /api/v1/openapi.json` | OpenAPI 3.1 spec (no token) |
| `GET /api/v1/providers` | sources and whether they are enabled |
| `GET /api/v1/search?q=<indicator>` | search one indicator (`only`, `offline`, `no_cache`) |
| `POST /api/v1/search` | search up to 100 indicators |
| `POST /api/v1/extract` | extract indicators from text |
| `POST /api/v1/enrich` | extract from an alert or text, search, and return an overall verdict |
| `GET /api/v1/cases` · `POST /api/v1/cases` | list or create cases |
| `GET /api/v1/cases/{name}` | a case with indicators, results and notes |
| `POST /api/v1/cases/{name}/indicators` | add indicators or free text, optionally searching them |
| `GET /api/v1/cases/{name}/export?format=` | export as `json`, `md`, `stix` or `navigator` |

```sh
curl -H "Authorization: Bearer $ASTRO_TOKEN" "http://127.0.0.1:8080/api/v1/search?q=8.8.8.8"
curl -H "Authorization: Bearer $ASTRO_TOKEN" -H "Content-Type: application/json" \
     -d '{"text":"beacon to hxxps://evil[.]example[.]com from 203.0.113.7"}' \
     http://127.0.0.1:8080/api/v1/enrich
```

Tokens are 256-bit random values stored only as SHA-256 hashes; manage them with
`astro token list` and `astro token revoke <name>`. Requests are rate limited per
token and bodies are capped at 1 MB. To expose the API beyond localhost pass
`--allow-remote` and serve it over TLS (`--tls-cert`/`--tls-key` or a reverse proxy).

### SOAR / EDR integration

`/enrich` is designed for automation. For example, a SentinelOne Singularity
Hyperautomation workflow (or any SOAR) can send the alert JSON as `text` with an
HTTP action and branch on `verdict` (`malicious`, `suspicious`, `clean`), using
`malicious` and `suspicious` to list the offending indicators.

## Configuration

astro reads its settings from `config.toml` in its data directory
(`$ASTRO_DATA_DIR`, or `~/.config/astro` on Linux,
`~/Library/Application Support/astro` on macOS, `%AppData%\astro` on Windows).
The file must be readable only by its owner (`chmod 600`).

```toml
http_timeout = "20s"
cache_ttl = "24h"

[keys]
nvd = "..."
```

Environment variables override the file: see [`.env.example`](.env.example).

### API keys

Every key is free and optional: sources without a key are skipped.

| Source | Where to get it | Free tier |
|---|---|---|
| VirusTotal | sign up at [virustotal.com](https://www.virustotal.com/gui/join-us), then [API key](https://www.virustotal.com/gui/my-apikey) | 4 requests/min, 500/day, non-commercial use |
| abuse.ch (MalwareBazaar, ThreatFox, URLhaus) | log in at [auth.abuse.ch](https://auth.abuse.ch/) and create an Auth-Key | one key for all abuse.ch services, fair use |
| AbuseIPDB | sign up at [abuseipdb.com](https://www.abuseipdb.com/register), then [API](https://www.abuseipdb.com/account/api) | 1,000 IP checks/day |
| AlienVault OTX | sign up at [otx.alienvault.com](https://otx.alienvault.com/), key under *Settings* | generous rate limit |
| Shodan | sign up at [account.shodan.io](https://account.shodan.io/register), key on the account page | limited query credits; [InternetDB](https://internetdb.shodan.io/) needs no key |
| GreyNoise | sign up at [viz.greynoise.io](https://viz.greynoise.io/signup), key under *Account → API Key* | Community API, limited lookups |
| NVD | request at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) (activated by email) | raises the limit from 5 to 50 requests per 30s |

Limits change over time: check each provider's terms.

## Development

Everything runs in Docker: no Go toolchain is needed on the host.

To try astro without installing anything, open a shell in a container with
`astro` built and on the `PATH`. Keys from `.env` are loaded only here (tests and
linters run without them) and datasets persist in the `astro-data` volume:

```sh
make try
astro sync
astro search CVE-2021-44228 T1059.001 "Lazarus Group"
exit
```

```sh
make help     # list targets
make test     # go test -race
make check    # verify, vet, staticcheck, gosec, govulncheck, tests
make run ARGS="search CVE-2021-44228"
make token NAME=soar   # create an API token
make serve    # web interface and REST API on http://127.0.0.1:8080
make cross    # release archives for every OS/arch in dist/
make clean    # remove containers and build output
```

## Security

- Lookups only contact the fixed API hosts of each source; searched URLs and
  domains are sent as data and never fetched.
- API keys are never logged or printed, and error messages strip query strings.
- Provider data is treated as untrusted: control characters are stripped
  before reaching the terminal.
- Outbound HTTPS requires TLS 1.2+, redirects never downgrade to HTTP and
  response sizes are capped.
- The database and config are created with owner-only permissions.
- Dependencies are kept minimal and checked with `govulncheck` in CI.

Please report vulnerabilities privately through GitHub security advisories.

## License

[MIT](LICENSE)
