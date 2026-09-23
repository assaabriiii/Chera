# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Report them
privately through
[GitHub's security advisories](https://github.com/assaabriiii/chera/security/advisories/new).
Include the version (`chera --version`), your OS, and steps to reproduce.

You can expect an acknowledgement within a week. Fixes are released as a new
version, and the advisory is published once users have had time to update.

## What counts

For example:

- a crafted DNS, TLS or HTTP response that crashes Chera or makes it hang;
- output that leaks information Chera promises not to include (local IP
  addresses, proxy credentials);
- any network traffic Chera sends that is not documented in the README.

## Design commitments

- Chera sends no telemetry and uploads nothing.
- It only connects to the targets being diagnosed, the public resolvers and
  baseline hosts listed in the README, the targets' official status pages and,
  with `--speed`, a baseline download.
- Reads are bounded (64 KB for HTTP checks, 1 MB for speed tests) and every
  network operation has a timeout.
- Release binaries are built by GitHub Actions with GoReleaser and published
  with SHA-256 checksums.
