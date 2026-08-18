# Releasing `maindala`

This package publishes to npm via **trusted publishing (OIDC)** — CI exchanges a
short-lived, workflow-scoped OIDC token for publish rights on every release. No npm
token is stored anywhere, in this repo or in the `maindala` org's secrets. This
replaces the old flow of an owner running `npm publish` locally behind an interactive
2FA prompt.

## How to cut a release

1. Bump `version` in `package.json` and add a dated entry to `CHANGELOG.md` **in the same
   release-prep commit** — `## [X.Y.Z] - YYYY-MM-DD` with today's real date, not
   `Unreleased`, not `TBD`, not left blank. **This needs a PR, not a direct push** — `main`'s
   branch protection has `enforce_admins: true` and requires a pull request for every
   change, with no path-based exception and no admin bypass (confirmed directly: a plain
   `src/` change was rejected on direct push even from an account with `admin` permission
   on this repo). Squash merging is disabled repo-wide; use a merge-commit or rebase-merge.

   **The release will fail if you skip the changelog date.** `release.yml`'s `verify` job
   runs `scripts/check-changelog-date.mjs`, which fails the release before `npm publish`
   runs if the top `CHANGELOG.md` entry isn't a real ISO date matching both `package.json`
   and the tag being released. **`CHANGELOG.md` does not ship inside the published
   tarball** — verified directly with `npm pack` + `tar -tzf`: only what `package.json`'s
   `files` field lists (`dist`, `bin`) plus npm's always-included `package.json`/
   `README.md`/`LICENSE` are in it. The actual reason to get this right before tagging is
   simpler and holds regardless: `CHANGELOG.md` in this repo is the permanent, public
   record of what shipped in each release, and a release cut while the top entry still
   reads "Unreleased" or "TBD" is a real, visible defect in that record at exactly the
   moment it's supposed to be authoritative. (The repo file itself *can* be corrected
   afterward if this gate is ever bypassed or fails to catch a bad entry — see the
   `ac94053` commit, which did exactly that for `0.1.12` — but a release should never
   depend on needing that fix.)
2. If the change additionally touches `.github/` — most importantly `release.yml` itself —
   `.github/CODEOWNERS` requires that PR to be approved by an owner before it can merge, on
   top of the plain PR requirement every change already has. This is deliberate: an
   unreviewed edit to the publish workflow could grant publish rights to a different
   repo/branch/environment, which would defeat the whole point of the required-reviewer
   gate on the workflow it edits.
3. Cut the release, which is what actually triggers `release.yml`:
   ```
   gh release create vX.Y.Z --title "vX.Y.Z" --notes-from-tag
   ```
   (or use the GitHub UI: Releases → Draft a new release → publish). **Publishing the
   release is the publish trigger** — nothing before this step calls `npm publish`.
4. Watch the Actions run. The `verify` job re-builds, type-checks, and re-tests the
   released commit from a clean checkout (this package has no offline `examples` script,
   unlike `@maindala/agent-guard`/`@maindala/telemetry` — its 83 vitest tests are the
   regression net). The `publish` job then **pauses** behind the `npm-publish`
   Environment until the configured reviewer approves it in the Actions UI — that
   approval click is the human gate, replacing the old interactive npm 2FA step.
5. Once approved, `npm publish` runs with `id-token: write` and no stored credential.
   `maindala` is an **unscoped** package, so no `--access public` flag is needed —
   unscoped packages publish public by default (unlike the scoped `@maindala/*`
   packages, which require the flag or they'd default to restricted). Provenance is
   generated automatically as part of the OIDC exchange — verify afterward with
   `npm view maindala` (should show a provenance attestation) and `npm audit signatures`.

Pushing a `main` commit or merging a PR **does not publish anything** — only a
published GitHub Release does. This is deliberate (see the design doc's §6.1): a merge
must not be able to publish.

## One-time setup this depends on — owner action, not automatable

Trusted publishing has to be configured on **npmjs.com itself** (there is no GitHub API
for this) before the first release through this workflow will succeed. On the
package's settings page (`npmjs.com` → `maindala` → Settings → Trusted
Publisher → GitHub Actions), enter exactly:

| Field | Value |
|---|---|
| Organization or user | `maindala` |
| Repository | `cli` |
| Workflow filename | `release.yml` (filename only, not the full path) |
| Environment name | `npm-publish` |
| Allowed actions | `npm publish` |

Also required (verified against npm's live docs 2026-08, per the design doc's §6.1
build-time caveat): **npm CLI >= 11.5.1** and **Node >= 22.14.0** in the publish job —
`release.yml` already pins Node 24 and force-installs the latest npm CLI, so nothing
further is needed there once the npmjs.com side is configured.

The GitHub side is already in place: the `npm-publish` Environment exists on this repo
with a required reviewer configured. If npm ever needs it, the environment name is
`npm-publish`.

## Break-glass path

If trusted publishing is ever broken or unavailable, `scripts/publish-package.sh` in
the private monorepo remains the documented fallback for this package too — see that
script's own header comment for the full `gitHead` provenance story this exists to
avoid repeating (for `maindala`, the CLI has no `.git` of its own in the staged
directory, so `gitHead` is correctly absent from the published manifest either way —
an honest absence, not a leak).
