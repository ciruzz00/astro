# astro

A threat intelligence search engine. One query, every source: hashes, IPs,
domains, URLs, CVEs, MITRE ATT&CK IDs, MAC addresses and threat names are
detected automatically and looked up across many intelligence feeds at once.

Built for incident response, threat hunting and CTF/DFIR challenges
(Hack The Box Sherlocks, TryHackMe).

> **Status:** early development. The CLI and all the sources below work;
> REST API, web UI, TUI, cases and PDF reports are on the roadmap.

## Features

- **Automatic detection** of MD5/SHA1/SHA256/SHA512, IPv4/IPv6, domains, URLs,
  emails, CVEs, ATT&CK IDs (`T1059.001`, `TA0002`, `G0032`, `S0154`, `M1036`,
  `C0022`), MAC addresses and free-text names (`"Lazarus Group"`).
- **Defanged input** accepted: `hxxps://evil[.]com`, `1.2.3[.]4`, `user[@]evil[.]com`.
- **IOC extraction** from logs, reports and emails, with de-duplication.
- **Offline datasets:** MITRE ATT&CK (enterprise, mobile, ICS), CISA KEV and
  the IEEE MAC registry, searchable without network access.
- **Parallel lookups** with per-source timeouts, rate limits and a local cache.
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
