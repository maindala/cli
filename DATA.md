# What this CLI transmits

This page documents exactly what data each command sends over the network, and to whom.
The short version: most commands need a personal API key and talk to
`https://api.maindala.com`; `maindala tail`'s free tier and `maindala scan`'s local report
need neither an account nor a network call at all.

## `maindala scan`

| Mode | Network call? | What is sent |
|---|---|---|
| `maindala scan [path]` (any format — table/json/sarif) | **One read call per MCP server** found in an `.mcp.json`/`claude_desktop_config.json` file, to the public, unauthenticated `GET /services/search` + `GET /services/:slug/trust` — this is the §3.1 catalog-matching step and runs by default, in every format, not only with `--register`. | Only the extracted package name or hostname of each MCP server entry (e.g. `@modelcontextprotocol/server-filesystem`), used solely as a search query. Nothing about your repository, its other findings, or any file content is sent. **No API key is required or used for this call.** If you are offline or the request fails for any reason, the scan completes anyway with matches simply omitted — this call is never required for the report to finish. |
| `... --timestamp` | One additional call, to a public RFC 3161 Time-Stamp Authority (`https://freetsa.org/tsr` by default, overridable via `MAINDALA_TSA_URL`) | Only the **SHA-256 digest** of the SARIF report — 32 bytes, not reversible to the report's content. The TSA never sees your findings, file paths, or repository. |
| `... --register --org <slug>` | Authenticated call to `POST /orgs/:slug/external-agents/discovered` | For each finding: its stable identity (`sourceRef`), a human-readable name, the detected platform/framework, its confidence tier, and (for MCP servers) any catalog match. **File content is never sent** unless you also pass `--include-definitions`. |
| `... --register --include-definitions` | Same endpoint | Everything above, **plus** the specific evidence that triggered the finding (e.g. the matched dependency line, the definition filename) so the server can run its trust-scanning heuristics. Still not your full source tree — only the evidence for findings that were actually detected. |

**In every mode**, findings are also written to a local `manifest.json` + SARIF/JSON file if
you asked for one (`--output`) — that file never leaves your machine unless you choose to
send it somewhere (a signing tool, a CI artifact store, `--register`).

**A repo with no `.mcp.json`/`claude_desktop_config.json` file makes zero network calls in
any mode** — the catalog-matching call only fires when there is an MCP server entry to look
up in the first place.

## `maindala tail`

See the `--help` text for `maindala tail`. The free tier (`--signup`) sends only an email
address to mint a token; the live stream itself is metadata only — tool name, target,
decision, latency — never prompts, tool arguments, or results.

## Everything else (`install`, `run`, `login`, `whoami`, `init`, `verify-pack`)

- `install`/`run` fetch public catalog content (skill/agent packages, agent bundles) using
  your personal API key for attribution and access control. `run` additionally pulls a
  public Docker image and passes your own LLM API key to the container you run locally —
  that key is never sent to mAIndala.
- `login`/`whoami` only read/write your local `~/.maindala/config.json`.
- `init` writes a local example file; no network call.
- `verify-pack` is fully offline — it only reads files you already have on disk.
