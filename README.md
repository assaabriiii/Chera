# Chera

**Chera** (Persian: چرا, "why?") is a network diagnosis CLI that explains *why* a
service is unreachable, not just *that* it is.

[فارسی](README.fa.md) · [How it works](docs/how-it-works.md) · [Contributing](CONTRIBUTING.md)

[![CI](https://github.com/assaabriiii/chera/actions/workflows/ci.yml/badge.svg)](https://github.com/assaabriiii/chera/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

Developers on filtered networks (in Iran and elsewhere) run into services that
"just don't work" all the time: GitHub, PyPI, npm, Docker Hub, Hugging Face, AI
APIs. `ping` and `curl` only say *failed*. The real cause could be any of these:

- DNS poisoning, or DNS queries hijacked on the way
- IP blocking
- SNI-based filtering of TLS connections
- a government block page
- the **provider itself** blocking your country (sanctions or export control)
- throttling
- a broken local connection
- an ordinary outage at the provider

Each cause needs a different fix, so guessing wastes hours. Chera runs layered
tests against each service and reports the most likely cause, with evidence, a
confidence level and a suggested next step.

```text
$ chera

TARGET                            VERDICT             CONF  EXPLANATION
github.com                        OK                  high  Reachable; the real service answered HTTP 200
api.github.com                    OK                  high  Reachable; the real service answered HTTP 200
raw.githubusercontent.com         SNI_FILTERED        high  TLS is reset right after the ClientHello for this name, but works with another SNI (also: DNS_POISONED)
objects.githubusercontent.com     SNI_FILTERED        high  TLS is reset right after the ClientHello for this name, but works with another SNI
codeload.github.com               OK                  high  Reachable; the real service answered HTTP 301
pypi.org                          DNS_POISONED        high  DNS answered 10.10.34.35, a known block-page address
files.pythonhosted.org            OK                  high  Reachable; the real service answered HTTP 404
registry.npmjs.org                OK                  high  Reachable; the real service answered HTTP 200
registry-1.docker.io              PROVIDER_GEO_BLOCK  high  The real service answered HTTP 403 with an unsupported-region message
auth.docker.io                    PROVIDER_GEO_BLOCK  high  The real service answered HTTP 403 with an unsupported-region message
production.cloudflare.docker.com  SNI_FILTERED        high  TLS stalls after the ClientHello for this name, but works with another SNI
proxy.golang.org                  IP_BLOCKED          high  TCP connections to 142.250.185.81 time out (packets are dropped)

Summary: 3 of 12 services blocked by SNI filtering; 2 of 12 blocked by the provider for your region; DNS is poisoned for 1; 1 of 12 blocked by IP; 5 of 12 services reachable
Checked 12 targets in 6.4s.

What to do:
  - SNI_FILTERED (raw.githubusercontent.com, objects.githubusercontent.com): The network filters TLS connections by the server name (SNI); DNS changes will not help. For Git, a mirror of the repository or a release asset mirror may help.
  - DNS_POISONED (pypi.org): DNS is poisoned: use a DNS-over-HTTPS or DNS-over-TLS resolver in your OS or browser, then re-run chera. For packages, use a reachable PyPI mirror (pip --index-url or pip config).
  - PROVIDER_GEO_BLOCK (registry-1.docker.io, auth.docker.io): The provider blocks your region: this is not a local network problem, and DNS or network changes will not fix it. For images, configure a reachable registry mirror (registry-mirrors in daemon.json).
  ...
```

*The output above is illustrative: it shows how different causes are reported
side by side. What you see depends on your network.*

## Features

- **One verdict per service**, with a confidence level (high, medium, low) and
  the evidence behind it.
- **Layered diagnosis**: local network, DNS (system, plain UDP and
  DNS-over-HTTPS), TCP, TLS/SNI, HTTP, optional throttling test, and official
  status pages.
- **Tells filtering apart from sanctions**: a provider refusing your region is
  reported as `PROVIDER_GEO_BLOCK`, because changing DNS or your network will
  not fix it.
- **Presets** for GitHub, Python, Node, Docker, Hugging Face, AI APIs, Go and
  Rust, defined in YAML you can extend.
- **Output for humans and machines**: a colored table, `--json`, and
  `--markdown` for pasting straight into a GitHub issue.
- **English and Persian** output (`--lang fa`), detected from your locale.
- **A single static binary** with no runtime dependencies, for Linux, macOS
  and Windows (amd64 and arm64).
- **Gentle and private**: a handful of connections per service, no scanning, no
  retries, and no telemetry. Chera never sends your data anywhere.

## Installation

### Release binaries (recommended)

Download the archive for your system from the
[releases page](https://github.com/assaabriiii/chera/releases), check it
against `checksums.txt`, and put the `chera` binary on your `PATH`.

```sh
# Linux / macOS example (replace VERSION, OS and ARCH)
curl -LO https://github.com/assaabriiii/chera/releases/download/vVERSION/chera_VERSION_OS_ARCH.tar.gz
curl -LO https://github.com/assaabriiii/chera/releases/download/vVERSION/checksums.txt
sha256sum --ignore-missing -c checksums.txt     # macOS: shasum -a 256 --ignore-missing -c checksums.txt
tar xzf chera_VERSION_OS_ARCH.tar.gz
sudo mv chera /usr/local/bin/
```

On Windows, download the `.zip`, compare its hash with
`Get-FileHash chera_VERSION_windows_amd64.zip`, and extract `chera.exe`.

If GitHub itself is hard to reach from your network, ask someone to download a
release for you and share it with its `checksums.txt`: the binary has no
dependencies and the checksum proves it has not been modified.

### With Go

```sh
go install github.com/assaabriiii/chera/cmd/chera@latest
```

### From source

```sh
git clone https://github.com/assaabriiii/chera.git
cd chera
go build -o chera ./cmd/chera
```

## Usage

```sh
chera                          # run the default developer preset
chera github.com               # diagnose one host
chera pypi.org files.pythonhosted.org
chera https://api.openai.com/v1/models   # use a specific URL for the HTTP check
chera --preset ai              # AI APIs
chera --preset python          # PyPI
chera --preset docker          # Docker Hub
chera --preset all             # every built-in target
chera --list-presets           # show presets
chera --verbose github.com     # every test and its raw evidence
chera --json                   # machine-readable output
chera --markdown > report.md   # a report ready to paste into an issue
chera --speed                  # also check for throttling
chera --lang fa                # Persian output
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--preset NAME` | `dev` | Preset to run. See `--list-presets`. |
| `--json` | | Print JSON. |
| `--markdown` | | Print a Markdown report for GitHub issues. |
| `-v`, `--verbose` | | Show every test and its raw evidence. |
| `--timeout D` | `5s` | Timeout for each network operation. |
| `--proxy URL` | | Send TCP connections through a proxy (`http://host:port` or `socks5://host:port`). Use it to test a path through your own proxy. |
| `--resolver R` | | An `IP[:port]` replaces the system resolver as the resolver under test; an `https://` URL is added as a trusted DoH reference. |
| `--speed` | | Measure handshake time and throughput and flag throttling. |
| `--lang en\|fa` | from locale | Output language. |
| `--concurrency N` | `8` | Targets checked in parallel. |
| `--no-color` | | Disable colors (`NO_COLOR` is honored too). |
| `--presets FILE` | | Extra presets YAML. |
| `--signatures FILE` | | Extra signatures YAML. |
| `--list-presets` | | List presets and exit. |
| `--version` | | Print the version. |

Exit codes: `0` when every target is `OK`, `1` when at least one is not, and
`2` for usage or configuration errors.

## Verdicts

Every target gets exactly one primary verdict. When a second problem is found
on the way (for example DNS poisoning on top of SNI filtering), it is listed as
`also:`.

| Verdict | What it means | What usually helps |
|---|---|---|
| `OK` | The real service answered over a verified path. | Nothing to fix. |
| `LOCAL_NETWORK_DOWN` | No active interface, no default route, or no well-known host is reachable at all. | Fix Wi-Fi, cable, modem or router first. |
| `DNS_POISONED` | Your resolver returns a block-page address, a private address, an address that does not serve the site, or claims the name does not exist, while DNS-over-HTTPS resolves it correctly. | Use an encrypted resolver (DoH/DoT). |
| `DNS_INTERCEPTED` | DNS traffic is hijacked on the path: a query to an address that runs no DNS server got an answer, or queries to public resolvers are rewritten. Changing the resolver IP will not help. | Use an encrypted resolver (DoH/DoT). |
| `IP_BLOCKED` | Connections to the service's correct addresses time out: packets are silently dropped. | DNS changes will not help; use a mirror. |
| `CONNECTION_RESET` | Connections to the correct addresses are actively refused or reset. | DNS changes will not help; use a mirror. |
| `SNI_FILTERED` | The TLS handshake dies right after the ClientHello for the real name, while the same address answers another name. | DNS changes will not help; use a mirror. |
| `TLS_INTERCEPTED` | The certificate does not validate, or comes from a known TLS inspection product. | Do not send credentials; ask the network administrator. |
| `BLOCK_PAGE` | The response is a government or ISP block page. | Network filtering; use a mirror. |
| `PROVIDER_GEO_BLOCK` | The **real** service refuses your region (HTTP 403/451 with an unsupported-region message). | Not a network problem: DNS and network changes will not fix it. |
| `THROTTLED` | The service works but is severely slower than a baseline host (`--speed`). | Retry later or use a mirror. |
| `UPSTREAM_OUTAGE` | The network path is clean but the service returns 5xx errors, or its status page reports an incident. | Wait; check the status page. |
| `INCONCLUSIVE` | No clear cause. | Run with `--verbose` and share the `--markdown` report. |

Suggestions describe the cause and generic remedies (encrypted DNS, package
mirrors, waiting for the provider). Chera does not bundle or recommend specific
circumvention services.

### Confidence

- **high**: the evidence points to one cause, e.g. a known block-page IP in the
  DNS answer, or an SNI reset while a neutral SNI works on the same address.
- **medium**: the evidence is consistent with the cause, but another
  explanation is possible (e.g. a refused connection could also be a server
  that is down).
- **low**: a best guess; look at `--verbose`.

## How detection works

For each target Chera runs these layers in order. Each one produces evidence,
which the verdict engine combines. The [How it works](docs/how-it-works.md)
guide explains every layer for developers who are not network experts.

1. **Local network**: interfaces, default route, reachability of well-known
   anycast hosts, and detection of proxy variables, OS proxy settings and VPN
   interfaces, so results are not misread.
2. **DNS**: resolves through the system resolver, plain UDP to public
   resolvers, and DNS-over-HTTPS (Cloudflare, Google, Quad9, dialed at fixed
   IPs). Answers are checked against known block-page IPs (such as
   `10.10.34.34`–`10.10.34.36`) and private ranges, and compared with DoH. A
   query sent to an address with no DNS server detects interception.
3. **TCP**: connects to port 443 on the correct (DoH) addresses and tells a
   timeout (blackhole) from a reset.
4. **TLS / SNI**: handshakes with the real SNI and validates the certificate.
   If that fails on the network, it retries with a neutral SNI and with no
   SNI; if those succeed, the name is being filtered.
5. **HTTP**: requests a lightweight URL from the verified address and
   classifies the response: block page, provider geo-block, server error, or
   normal.
6. **Throttling** (`--speed`): compares handshake time and throughput with a
   baseline download.
7. **Outage check**: when the path is clean but the service fails, asks the
   official status page.

## Presets

| Preset | Targets |
|---|---|
| `github` | github.com, api.github.com, raw.githubusercontent.com, objects.githubusercontent.com, codeload.github.com |
| `python` | pypi.org, files.pythonhosted.org |
| `node` | registry.npmjs.org |
| `docker` | registry-1.docker.io, auth.docker.io, production.cloudflare.docker.com |
| `huggingface` | huggingface.co, cdn-lfs.huggingface.co |
| `ai` | api.openai.com, api.anthropic.com, generativelanguage.googleapis.com |
| `go` | proxy.golang.org |
| `rust` | crates.io |
| `dev` (default) | github, python, node, docker, go |
| `all` | every built-in target |

Presets live in [`internal/presets/presets.yaml`](internal/presets/presets.yaml)
and are embedded in the binary. To add your own, create
`presets.yaml` in your user config directory (`~/.config/chera/` on Linux,
`~/Library/Application Support/chera/` on macOS, `%AppData%\chera\` on
Windows), or pass `--presets FILE`:

```yaml
presets:
  work:
    description: Services my team depends on
    targets:
      - host: git.example.com
        url: https://git.example.com/api/v4/version
      - host: registry.example.com
        url: https://registry.example.com/v2/
        kind: docker
  mine:
    include: [github, work]
default: mine
```

Block-page addresses, block-page contents, geo-block messages and TLS
inspection issuers are defined in
[`internal/signatures/signatures.yaml`](internal/signatures/signatures.yaml)
and can be extended the same way with `signatures.yaml` or `--signatures FILE`.

## JSON and Markdown

`--json` prints the full report, including every piece of evidence, the
translated explanation and suggestion, and a count per verdict. `--markdown`
prints a report with an environment summary, the results table, suggestions and
a collapsible evidence section, ready to paste into a GitHub issue.

Neither format contains your local IP addresses. Proxy environment variables
are reported by name only, never by value.

## Privacy

Chera only talks to the services it diagnoses, the public DNS resolvers listed
above, the baseline hosts (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`), the official status
pages of the targets, and, with `--speed`, a baseline download from
`speed.cloudflare.com`. It sends no telemetry and uploads nothing.

## Contributing

Contributions are very welcome, especially new presets and block-page or
geo-block signatures from networks we have not seen yet. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
