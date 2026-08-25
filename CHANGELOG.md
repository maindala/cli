# Changelog

All notable changes to `maindala` (the CLI) are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions below are backfilled
against what is actually live on npm (`npm view maindala versions`/`npm view maindala time`,
checked 2026-08-11), not just what shipped in source. This is the first release with a
CHANGELOG.md — everything through 0.1.11 is a historical backfill.

## [0.4.0] - 2026-08-24

### Added
- `maindala tail --signup <email>` now accepts an optional `--company <name>` and a
  `--contact-me` flag. Neither is required — an existing script or CI job calling
  `--signup` with no other flags behaves exactly as before. When you run
  `--signup` interactively (a real terminal, no `--company`/`--contact-me` given) you're
  now asked once for an optional company and whether mAIndala may email you about team
  governance — declining (a bare Enter) is the default, and a non-interactive
  invocation is never prompted. Opting in creates a follow-up contact request on
  mAIndala's side; supplying a company alone does not.

## [0.3.0] - 2026-08-19

### Added
- `maindala tail <org-slug>` now streams `[alert]` events from the org's detection sweep
  (rule id, severity, subject, title, status, occurrence count) alongside existing
  `[tool]`/`[a2a]` decisions — org-scoped only, since alerts are inherently org-scoped and
  the endpoint requires the same admin-gated key as the existing streams; no free/mt_-tier
  equivalent. A repeating alert (occurrence count bumped by the sweep's dedup) is shown
  again as "still happening," not just on first sighting.
- `maindala verify-pack <directory>` now also verifies a `maindala scan --format sarif`
  output directory (manifest.json + artifact), detected automatically from the manifest's
  shape — no flag needed. Checks the artifact's digest and, if present, the RFC 3161
  timestamp token. The existing Compliance Evidence Pack verification path is unchanged.

### Fixed
- `verify-pack`'s RFC 3161 timestamp check for a scan manifest was verifying against the
  already-hashed digest bytes instead of the original artifact bytes, causing every
  genuine timestamp token to report INVALID — caught via a real TSA round trip during
  development, not a synthetic test. Fixed before this ever shipped; a frozen fixture from
  that real round trip now regression-tests it.

## [0.2.0] - 2026-08-17

### Added
- `maindala scan [path]` — discovers AI agents and MCP integrations in a local codebase.
  No account or API key required for the local report, and it completes even offline.
  Three confidence tiers: dependency manifests (`package.json`/`requirements.txt`/
  `pyproject.toml`/`go.mod`, high confidence), MCP client config / crew-agent definition
  files (`.mcp.json`/`claude_desktop_config.json`/`crew.yaml`/`agents.yaml`, high
  confidence), and source-code patterns (`StateGraph(`, `Crew(`, `new Client(`, low
  confidence — **never** auto-registered, even with `--register`). MCP servers found in a
  config file are matched against the public catalog for context (trust status, check
  count) via one unauthenticated lookup per server.
- `--format sarif --output <path>` emits an OASIS SARIF 2.1.0 report plus a sidecar
  `manifest.json` (SHA-256 digest, versioned format) — a local, signable record the caller
  can hand to their own signing infrastructure (cosign, GPG, an in-house TSA) before
  anything is pushed to mAIndala. Output is byte-deterministic across repeated runs against
  unchanged input (sorted results, no wall-clock timestamp in the signed body,
  repo-relative paths only — see the test suite's dedicated determinism checks).
- `--timestamp` additionally fetches a free RFC 3161 timestamp token over the manifest
  digest from a public Time-Stamp Authority (`https://freetsa.org/tsr` by default,
  overridable via `MAINDALA_TSA_URL`), anchoring the local record to a third party without
  mAIndala retaining anything.
- `--register --org <slug>` pushes findings into that org's governed agent registry
  (requires `maindala login <mk_...>` as a member of the org — not an admin-only action).
  Metadata only by default; `--include-definitions` additionally sends the specific
  evidence that triggered each finding, enabling server-side trust scanning.
- `DATA.md` — documents exactly what every command transmits, and to whom, including the
  new per-flag breakdown for `scan`.

## [0.1.12] - 2026-08-11

Date corrected after the fact (confirmed via `npm view maindala time --json`, not
guessed) — this repo had the identical "published as Unreleased" defect found and fixed
in `@maindala/agent-guard`'s `1.0.1` (this heading was still "Unreleased" while `0.1.12`
was already live on npm). **The published `0.1.12` tarball on npm still contains this
heading as "Unreleased"** — `CHANGELOG.md` ships inside the tarball built at publish
time, and npm versions are immutable, so that copy can never be corrected. Only this repo
copy, and only going forward (via the new `scripts/check-changelog-date.mjs` release
gate — see RELEASING.md), is fixed.

### Fixed
- `--help` output for `maindala init` named an internal initiative codename and phase
  number ("Free Telemetry Wedge P3") instead of describing the command. Confirmed present
  in the published `dist/index.js` for 0.1.11. Same codename, and two internal services'
  private codenames, genericized out of source comments in `init.ts`/`tail.ts`/`runner.ts`
  — comment-only, no behavior change. The private-terms sweep list gained the bare
  service-codename forms so this class is caught mechanically next time instead of by eye
  (it previously listed only the path-qualified forms). (QFX-2)

### Added
- Vitest suite (83 tests across 4 files) covering the three safe-path call sites added in
  0.1.9 (`safe-path.ts`, `runner.ts`'s file-write path, `verify-pack.ts`) plus all 10
  install-format writers — traversal, absolute paths, null bytes, and the legitimate cases
  that must still pass. No behavior change; coverage only.

### Changed
- `repository`/`homepage`/`bugs` now point at this package's own public source repo,
  `github.com/maindala/cli` (extracted from the private monorepo as a source-reviewable
  mirror), instead of being absent.

## [0.1.11] - 2026-08-09

### Fixed
- `maindala --version` printed a hardcoded `0.1.8` literal that had stopped tracking
  `package.json` across the 0.1.9 and 0.1.10 bumps — found by an external audit. Now reads
  the version from the installed `package.json` at runtime.
- `RUNTIME_IMAGE_TAG` (the pinned `agent-runtime` image `maindala run` pulls) was stale at
  `2.1.1` against a live production tag of `2.6.7` — found during the fix above, same
  defect class (a hardcoded constant nobody updates when the thing it mirrors moves).

## [0.1.10] - 2026-08-09

### Changed
- `MAINDALA_CATALOG_URL`-overridable default no longer points at the raw Cloud Run
  hostname — repointed to the now-public `https://api.maindala.com`. Still fully
  overridable via the env var.
- Re-published solely to obtain a correct `gitHead` on the tarball: 0.1.9 had been
  published with a plain `npm publish` instead of through the project's publish script, so
  it carried a `gitHead` pointing at a private monorepo commit (npm records this at
  publish time and it cannot be edited afterward).

## [0.1.9] - 2026-08-09

### Fixed
- Publish path now writes correct npm `gitHead` provenance (previously every published
  version pointed at a private monorepo commit — a disclosure and a verification dead
  end); the pre-publish sweep for internal references now covers a wider set of terms.

## [0.1.8] - 2026-08-09

### Fixed
- **Arbitrary file write.** `runner.ts` wrote agent-runtime-returned output filenames as
  raw, unrooted paths with no path confinement — a server-controlled value with no
  containment, on the command whose entire purpose is running third-party agents. New
  `safe-path.ts` is now the shared confinement helper for this write path, for
  `verify-pack.ts`'s evidence-pack section names (which also had a digest-disclosure side
  channel in its mismatch message, also fixed), and for install-format writer slugs.

## [0.1.7] - 2026-07-24

### Added
- `maindala tail <org-slug>` — live, colorized tail of an org's governed tool calls and
  A2A delegations, via cursor-based polling against the catalog API's activity endpoints
  (existing `mk_`/session auth).
- `maindala tail --signup <email>` — zero-setup tail with no org/account required, backed
  by a new `mt_` telemetry token.
- `maindala init` — scaffolds `@maindala/telemetry` into the current project.

## [0.1.6] - never published

Built (compliance-evidence-packs P3: a `verify-pack <dir>` subcommand, an offline verifier
for signed evidence-pack exports) but never released to npm — the registry has no 0.1.6
and jumps 0.1.5 → 0.1.7. Recorded here for the historical record, not as a gap to fill.

## [0.1.5] - 2026-06-17

### Added
- `maindala run agent/<slug> --team <slug,slug,...>` — runs a multi-agent team locally
  (entry + up to 4 workers), assembling the same `TEAM_CONFIG` shape the platform's own
  deploy pipeline uses.

## [0.1.4] - 2026-06-17

### Added
- `maindala run agent/<slug>` — runs an agent locally in Docker against the public
  `agent-runtime` image, using the caller's own LLM key (no Cloud Run, no platform LLM
  cost). Server mode (`POST /run` on localhost) and one-shot mode (`--input`).

## [0.1.3] - 2026-06-16

### Added
- `claude-skill`, `zed`, `continue`, and `cline` local-install targets for `maindala
  install`, alongside the existing `claude`/`cursor`/`copilot`/`windsurf`/`openclaw`/`raw`.

### Fixed
- `--version` had been hardcoded to the stale literal `'0.1.0'` regardless of the actual
  package version; now reads from `package.json`.

## [0.1.2] - 2026-05-26

### Changed
- Internal `/personas/*` API routes renamed to `/agents/*`, following the platform-wide
  persona → agent rename. No user-facing CLI string changed (the CLI already said
  "Agent"/"Agents" everywhere).

## [0.1.1] - 2026-05-25

### Fixed
- Skill and agent package downloads 403'd for any user who had not first installed via the
  website, because 0.1.0 fetched metadata and the package in parallel. Now sequentially
  calls the (idempotent) install/deploy endpoint before fetching the package.

## [0.1.0] - 2026-05-25

### Added
- Initial release. `npx maindala install <slug>` with auto-detected target format
  (`claude`, `cursor`, `copilot`, `windsurf`, `openclaw`, `raw`) and Bearer `mk_` auth.
