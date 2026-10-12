# Changelog

All notable changes to Sigil are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security
- `sigil verify` no longer treats a valid signature as proof of who signed
  a badge. The signer must be trusted: listed via `--trusted-keys <file>` /
  `SIGIL_TRUSTED_KEYS`, your own `sigil keygen` key, or (online) indexed
  under the same key id. Unknown signers exit 1 unless `--allow-untrusted`
  is passed (prints an UNVERIFIED warning). An index entry whose key id
  differs from the badge's is rejected. **Behaviour change** for offline or
  unindexed verification.
- `verifyBadge(badge, { trustedKeyIds })` and `parseTrustedKeys()` added to
  the library API; `VerifyResult.trustedSigner` reports the outcome.

### Fixed
- Scanning a package whose `bin` map lists a CLI before the MCP server
  (e.g. `{"godmode": ..., "godmode-mcp": ...}`) no longer spawns the CLI:
  Sigil now prefers a bin named like `*-mcp`, then `*server*`, then the
  first entry.
- The behavioral pass no longer hangs forever when the target never
  answers `initialize`: the handshake is bounded (30s) and the spawned
  child is closed on failure, so the scan falls back to static-only.
- Server stderr is captured instead of inherited, so fuzzed payloads the
  server logs no longer flood the scan output. A short tail is attached
  to handshake errors; set `SIGIL_SERVER_STDERR=inherit` to see all of it.
- Fewer false positives: ``db.exec(`...${x}`)`` and other non-child_process
  `.exec()` method calls are no longer reported as shell injection.

### Added
- `sigil pin <server>[@<version>]`: resolve the verified install from the
  public trust index. Prints the exact `npm install -g` command, the
  registry integrity hash, and the badge summary. Refuses revoked versions;
  warns on superseded ones.
- `sigil install <server>[@<version>] [--dry-run]`: install the verified
  version after showing its badge. `--dry-run` previews without installing.
- `sigil revoke --server <s> --version <v> --reason <r> --key <keyfile>`:
  sign a badge revocation with the project maintainer key (submits as
  `revocations/<server>/<version>.json` via PR).
- `sigil verify` now checks the badge's index status
  (active / superseded / revoked) unless `--offline` is passed. Revoked
  badges exit 2 with the revocation reason.
- Badges record the exact installable `artifact`
  (`{ type: "npm" | "git" | "local", spec, integrity? }`) so pins are
  reproducible.

- Dependabot config for npm and GitHub Actions (weekly).
- `SECURITY.md` with a private vulnerability-reporting contact.
- `.env.example` listing the environment variables Sigil reads (`SIGIL_SKIP_AUDIT`).

### Changed
- The public trust index derives a per-badge status and shows it on the
  site and in the machine-readable manifest.

## [0.1.0] - 2026-10-03

Initial release.

### Added
- `sigil scan <target>`: static heuristics (tool capabilities, the
  lethal-trifecta shape, tool-description poisoning, secrets/egress/exec
  patterns, `npm audit`) plus behavioral evals (schema, conformance, and
  seeded fuzz oracles) against a live server.
- `sigil keygen`, `sigil verify`, `sigil publish`: Ed25519
  key management, self-contained badge verification, and badge submission
  to the public trust index via pull request.
- Risk scoring: every finding deducts from 100 on one documented schedule
  (critical 25 / major 12 / minor 4 / info 1); any critical finding forces
  the `critical` level.
- CI gating: `--fail-on` exits 2 when the risk level reaches the threshold.
