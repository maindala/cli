# maindala

[![CI](https://github.com/maindala/cli/actions/workflows/ci.yml/badge.svg)](https://github.com/maindala/cli/actions/workflows/ci.yml)

Install mAIndala Skills and Agents into your AI coding environment.

## Install

```bash
npx maindala install <skill-slug>
npx maindala install agent/<agent-slug>
```

## Authentication

Skills and Agents require a personal API key. Get one at https://www.maindala.com/profile.

```bash
# Save key permanently
npx maindala login mk_your_api_key_here

# Or use environment variable
MAINDALA_API_KEY=mk_... npx maindala install <slug>
```

## Formats

Auto-detected from your project, or specify with `--format`:

| Format | Tool | Output |
|--------|------|--------|
| `claude-skill` | Claude Code (native skills) | `.claude/skills/<slug>/SKILL.md` |
| `claude` | Claude Code | `CLAUDE.md` |
| `cursor` | Cursor | `.cursor/rules/<slug>.mdc` |
| `copilot` | GitHub Copilot | `.github/copilot-instructions.md` |
| `windsurf` | Windsurf | `.windsurfrules` |
| `openclaw` | OpenClaw | `.openclaw/skills/<slug>.md` |
| `continue` | Continue | `.continue/rules/<slug>.md` |
| `cline` | Cline / Roo | `.clinerules/<slug>.md` |
| `zed` | Zed | `.rules` |
| `raw` | Any | `./<slug>.md` |

Table order matches auto-detection priority (top to bottom). This list is checked against the CLI's
actual supported formats by `scripts/verify-readme-formats.mjs`, which fails if this table and the
CLI's own `Format` list ever drift apart again.

## Examples

```bash
# Install a skill into Claude Code (auto-detected if CLAUDE.md exists)
npx maindala install linkedin-connection-request

# Install an agent into Cursor
npx maindala install agent/stock-analyst-pro --format cursor

# Install with a specific API package format
npx maindala install full-equity-research-report --api-format openai
```

## Discover agents (`scan`)

```bash
# Local report — no account, no API key, works offline
npx maindala scan .

# Machine-readable report, signable before anything touches mAIndala
npx maindala scan . --format sarif --output scan.sarif
# writes scan.sarif + a sidecar manifest.json (SHA-256 digest) — sign the
# digest with your own infrastructure (cosign, GPG, an in-house TSA)

# Optionally anchor the digest with a free public RFC 3161 timestamp
npx maindala scan . --format sarif --output scan.sarif --timestamp

# Push findings into a governed org registry (requires `maindala login <mk_...>`)
npx maindala scan . --register --org my-org
```

Detects, at three confidence tiers, agent/LLM framework usage in the current
directory: dependency manifests (`package.json`, `requirements.txt`,
`pyproject.toml`, `go.mod`), MCP client config / crew-agent definition files
(`.mcp.json`, `claude_desktop_config.json`, `crew.yaml`, `agents.yaml`), and
(lowest confidence, never auto-registered) source-code patterns. MCP servers
found in a config file are matched against the public mAIndala catalog for
context (trust status, check count) — see [DATA.md](./DATA.md) for exactly
what is sent over the network in each mode, and to whom.

## Verify a signed evidence log export (`verify-log`)

```bash
# Is the export internally consistent? (never "verified" on its own)
npx maindala verify-log ./export

# Is it consistent AND signed by a key you trust? trust.json comes from outside the export
npx maindala verify-log ./export --trust trust.json

# Also check it against checkpoints you kept independently (detects rollback / rewritten history)
npx maindala verify-log ./export --trust trust.json --retained checkpoints.ndjson --json
```

Verifies a signed, append-only evidence log export offline: RFC 6962 Merkle tree,
C2SP signed-note checkpoints, Ed25519 signatures. Each segment reports a structural
outcome (`consistent`, `rolled_back`, `conflicting_history`, `broken`, with the first
failing index) and, separately, provenance (`authenticated`, `not_authenticated`,
`revoked`) judged only against the trust file. "Verified" means consistent **and**
authenticated. Exit codes: `0` verified, `1` consistent but not authenticated or not
fully related, `2` failed. It uses Node's built-in crypto only and makes no network
call. The export layout, `trust.json` format and the revocation-time limitation are in
[docs/verify-log-format.md](./docs/verify-log-format.md).

## Releasing

See [RELEASING.md](./RELEASING.md) — publishing runs through a GitHub Release +
trusted-publishing CI workflow with a required-reviewer approval gate, not a local
`npm publish`.
