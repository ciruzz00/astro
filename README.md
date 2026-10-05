# astro

A threat intelligence search engine. One query, every source: hashes, IPs,
domains, URLs, CVEs, MITRE ATT&CK IDs, MAC addresses and threat names are
detected automatically and looked up across many intelligence feeds at once.

Built for incident response, threat hunting and CTF/DFIR challenges
(Hack The Box Sherlocks, TryHackMe).

> **Status:** early development. The CLI and the offline/keyless sources work;
> keyed providers, REST API, web UI, TUI, cases and PDF reports are on the roadmap.

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

| Source | Indicators | API key |
|---|---|---|
| MITRE ATT&CK (offline) | ATT&CK IDs, group/software/campaign names | no |
| NVD | CVE | optional |
| CISA KEV (offline) | CVE | no |
| FIRST EPSS | CVE | no |
| IEEE OUI (offline) | MAC address | no |

Planned: VirusTotal, abuse.ch (MalwareBazaar, ThreatFox, URLhaus), AbuseIPDB,
AlienVault OTX, Shodan, GreyNoise.

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

## Development

Everything runs in Docker: no Go toolchain is needed on the host.

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
