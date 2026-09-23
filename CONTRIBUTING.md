# Contributing to Chera

Thank you for helping! Chera gets better with every network it has seen, so
reports from real filtered networks are as valuable as code. You do not need
to be a network expert to contribute: [How it works](docs/how-it-works.md)
explains every layer.

All contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to help

- **Report a misdiagnosis.** Run `chera --markdown` (add `--verbose` output if
  useful) and open an issue with the report and what you know about the real
  cause. Remove anything you consider private first; Chera never includes your
  local IP addresses, but the report does include the addresses of the services.
- **Add a preset** for services developers depend on (see below).
- **Add a block-page or geo-block signature** you have observed (see below).
- **Improve translations**, especially the Persian messages in
  [`internal/i18n/messages.go`](internal/i18n/messages.go), or add a new
  language.
- **Fix bugs, improve docs, add tests.** Issues labelled `good first issue`
  are a good place to start.

## Development setup

You need Go (the latest stable release is what CI uses) and Git.

```sh
git clone https://github.com/assaabriiii/chera.git
cd chera
go build ./cmd/chera        # build
go test ./...               # unit and integration tests
go test -race ./...         # what CI runs on Linux and macOS
go vet ./...
gofmt -l .                  # must print nothing
golangci-lint run           # optional locally, enforced in CI
```

The integration tests start fake DNS, DoH, TLS and HTTP servers on
`127.0.0.1`; they need no Internet access. `go test -short ./...` skips the
slower end-to-end ones.

### Project layout

```
cmd/chera/            entry point
internal/cli/         flags, target parsing, output selection
internal/probe/       runs the layers for each target (+ end-to-end tests)
internal/localnet/    layer 1: interfaces, route, baseline, proxy/VPN detection
internal/dnscheck/    layer 2: system/UDP/DoH resolvers, poisoning analysis
internal/dnswire/     minimal DNS message encoding/decoding
internal/tcpcheck/    layer 3: TCP connect classification
internal/tlscheck/    layer 4: TLS handshakes with real/neutral/no SNI
internal/httpcheck/   layer 5: HTTP response classification
internal/speed/       layer 6: throttling measurements
internal/outage/      layer 7: status page checks
internal/verdict/     the rule engine that picks one verdict
internal/signatures/  block-page IPs, block pages, geo-blocks (embedded YAML)
internal/presets/     target presets (embedded YAML)
internal/i18n/        English and Persian messages
internal/report/      table, JSON and Markdown output
internal/testutil/    fake servers used by tests
```

Each layer is its own package with its own table-driven tests. Layers never
decide verdicts; they only report what happened. All decisions live in
`internal/verdict`.

## Adding a preset

Presets are defined in [`internal/presets/presets.yaml`](internal/presets/presets.yaml).

```yaml
presets:
  mytool:
    description: Short description shown by --list-presets
    targets:
      - host: registry.mytool.dev
        # A small, stable URL. Avoid heavy pages and anything that needs
        # authentication to return quickly. 401/403/404 are fine: any
        # response from the real service proves the path works.
        url: https://registry.mytool.dev/health
        # Optional: a Statuspage-compatible status.json for outage checks.
        status_page: https://status.mytool.dev/api/v2/status.json
        # Optional: ecosystem for remedy hints (see below).
        kind: mytool
```

Guidelines:

- Pick a URL that returns a **small** response. Chera reads at most 64 KB.
- Add a `status_page` only if the URL really serves the Statuspage
  `/api/v2/status.json` format. Test it with
  `curl -s URL | head -c 300`.
- If the new preset is a common developer need, consider adding it to the
  `all` preset (and, rarely, to `dev`, which must stay fast).
- Update the counts in `internal/presets/presets_test.go` and the preset table
  in both READMEs.
- If you add a new `kind`, add a `hint.<kind>` message in
  `internal/i18n/messages.go` in **both** English and Persian. Hints must
  describe generic remedies only (mirrors, configuration options), never a
  specific circumvention service.

You can test a preset without rebuilding: put it in a file and run
`chera --presets my.yaml --preset mytool --verbose`.

## Adding a block-page or geo-block signature

Signatures live in [`internal/signatures/signatures.yaml`](internal/signatures/signatures.yaml).
They are what turns "something failed" into a precise verdict, so they must
be accurate. A wrong signature causes wrong diagnoses for everyone.

**Every new signature needs evidence in the pull request**: a captured
response (headers and the relevant part of the body, with anything personal
removed), the network or country where it was seen, the date, and ideally a
public source (a report, a news article, a measurement platform entry). Please
also include the output of `chera --verbose` or `--markdown` against the
affected service.

### Injected DNS addresses (`block_ips`)

Addresses that a filtering system returns in DNS answers instead of the real
one. Only add addresses that are **only** used for that purpose (typically
private or unrouted addresses of block-page servers). Never add an address
that also hosts legitimate services.

```yaml
block_ips:
  # Country/ISP: what it is, and where it was observed.
  - 10.10.34.34
```

### Block pages (`block_pages`)

Match either the redirect target (`url_contains`) or the page body
(`body_contains`). Matching is case-insensitive substring matching. Choose
strings that are **specific** to the block page: a portal domain or the
block-page server address, not generic words like "blocked".

```yaml
block_pages:
  - name: country-isp-short-name
    url_contains:
      - blockpage.example.net
    body_contains:
      - "http://blockpage.example.net/"
```

### Provider geo-blocks (`geo_blocks`)

Responses from the **real service** that refuse a region. Always restrict them
with `host_suffix` when the message is provider-specific, and with `status`
when you know the status code, so a similar sentence elsewhere cannot match.

```yaml
geo_blocks:
  - name: provider-unsupported-region
    host_suffix: provider.com
    status: [403]
    body_contains:
      - "exact phrase from the provider's error message"
```

### TLS inspection issuers (`interception_issuers`)

Certificate issuer organisation names of TLS inspection products. A valid
certificate chain issued by one of them yields `TLS_INTERCEPTED`.

### Tests

Add a case to `internal/signatures/signatures_test.go` with the real (trimmed)
response, and, if it exercises new logic, to
`internal/httpcheck/httpcheck_test.go` or `internal/dnscheck/dnscheck_test.go`.

## Changing the verdict logic

The rules are in [`internal/verdict/verdict.go`](internal/verdict/verdict.go)
and are covered by table-driven tests in `verdict_test.go` and end-to-end tests
in `internal/probe/integration_test.go`, which simulate every verdict with fake
servers (a DNS server that returns a block-page address, a TLS server that
resets a specific SNI, an HTTP server that serves a block page, and so on).

When you change a rule:

1. Explain in the pull request which real-world situation was misdiagnosed.
2. Add a test case that fails without your change.
3. Keep the principle that the verified network path wins over DNS, and that
   an uncertain situation gets a lower confidence rather than a wrong verdict.
4. If you add a verdict reason, add its message in English and Persian.

## Translations

Messages are in [`internal/i18n/messages.go`](internal/i18n/messages.go).
`TestPersianCoversEnglish` fails if a key is missing in Persian, and
`TestPlaceholdersMatch` fails if a `{placeholder}` is lost. Verdict names
(`SNI_FILTERED`, ...) and technical terms such as DNS, TLS and SNI stay in
English on purpose, so reports can be compared across languages.

To add a language, add a map in `messages.go`, extend `Parse` and `Detect` in
`i18n.go`, and add tests.

## Principles

These are not negotiable, and reviews will check them:

- **Privacy**: no telemetry, no uploads, no local IP addresses in reports, no
  proxy credentials in output.
- **Gentleness**: a handful of connections per target, no retries, no
  scanning, bounded reads.
- **Honesty**: explain the cause and generic remedies. Do not bundle or
  recommend specific circumvention services.
- **Portability**: a single static binary; prefer the standard library. New
  dependencies need a strong reason.
- **Testability**: every layer is testable without the Internet.

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/):
  `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`, optionally with a
  scope, e.g. `feat(signatures): add block page seen on ISP X`.
- Keep pull requests focused; one preset or signature per PR is ideal.
- Make sure `go test ./...`, `go vet ./...` and `gofmt -l .` are clean.
- Fill in the pull request template.

## Releases

Maintainers tag a version (`git tag v0.2.0 && git push origin v0.2.0`). The
release workflow runs the tests and GoReleaser, which builds Linux, macOS and
Windows binaries for amd64 and arm64 and publishes them with a
`checksums.txt`.
