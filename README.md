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
