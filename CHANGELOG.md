# Changelog

All notable changes are listed here. Release notes with every commit are
generated on the [releases page](https://github.com/assaabriiii/chera/releases).
This project follows [Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- Layered diagnosis: local network, DNS (system, plain UDP, DoH), DNS
  interception check, TCP, TLS/SNI, HTTP classification, optional throttling
  test, and status page outage check.
- Thirteen verdicts with confidence levels, reasons and suggestions.
- Presets for GitHub, Python, Node, Docker, Hugging Face, AI APIs, Go and Rust,
  extensible with YAML.
- Signatures for injected DNS addresses, block pages, provider geo-blocks and
  TLS inspection products, extensible with YAML.
- Table, JSON and Markdown output in English and Persian.
- `--proxy`, `--resolver`, `--timeout`, `--speed` and `--concurrency` flags.
