#!/usr/bin/env node
import { Command } from 'commander';
import fs from 'fs';
import path from 'path';
import {
  fetchSkillMeta,
  fetchAgentMeta,
  fetchSkillPackage,
  fetchAgentPackage,
  fetchAgentExport,
  autoInstallSkill,
  autoDeployAgent,
  saveApiKey,
  getApiKey,
} from './api.js';
import { writeFormat as writeToFormat, Format } from './writers.js';
import { runServer, runOneShot, resolveLlmKey, assembleTeamConfig, MAX_TEAM_AGENTS, PROVIDERS, DEFAULT_IMAGE, Provider, RunOptions, Payload } from './runner.js';
import { assertValidSlug, assertValidPort } from './safe-path.js';

const FORMATS: Format[] = [
  'claude', 'claude-skill', 'cursor', 'copilot', 'windsurf', 'openclaw', 'zed', 'continue', 'cline', 'raw',
];

function autoDetectFormat(): Format {
  const cwd = process.cwd();
  // Prefer the Claude Code native skill dir over CLAUDE.md when the project uses it.
  if (fs.existsSync(`${cwd}/.claude/skills`)) return 'claude-skill';
  if (fs.existsSync(`${cwd}/CLAUDE.md`)) return 'claude';
  if (fs.existsSync(`${cwd}/.cursor`)) return 'cursor';
  if (fs.existsSync(`${cwd}/.github/copilot-instructions.md`)) return 'copilot';
  if (fs.existsSync(`${cwd}/.windsurfrules`)) return 'windsurf';
  if (fs.existsSync(`${cwd}/.openclaw`)) return 'openclaw';
  if (fs.existsSync(`${cwd}/.continue`)) return 'continue';
  if (fs.existsSync(`${cwd}/.clinerules`)) return 'cline';
  if (fs.existsSync(`${cwd}/.rules`)) return 'zed';
  return 'raw';
}

// Read the real installed version instead of a literal that drifts on every
// bump (it did — 0.1.8 shipped inside 0.1.9 and 0.1.10 alike).
const pkg = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')
) as { version: string };

const program = new Command();

program
  .name('maindala')
  .description('Install mAIndala Skills and Agents into your AI coding tools')
  .version(pkg.version);

program
  .command('install <slug>')
  .description(
    'Install a skill or agent.\n' +
    '  Skill: maindala install <skill-slug>\n' +
    '  Agent: maindala install agent/<agent-slug>\n\n' +
    `  Formats: ${FORMATS.join(', ')}`
  )
  .option('-f, --format <format>', `output format (${FORMATS.join('|')})`)
  .option('--api-format <format>', 'raw API format override (raw, claude, openai, crewai, etc.)')
  .action(async (slug: string, options: { format?: string; apiFormat?: string }) => {
    const isAgent = slug.startsWith('agent/');
    const realSlug = isAgent ? slug.replace(/^agent\//, '') : slug;
    const fmt = (options.format as Format | undefined) ?? autoDetectFormat();
    const apiFormat = options.apiFormat ?? 'raw';

    if (options.format && !FORMATS.includes(options.format as Format)) {
      console.error(`Unknown format "${options.format}". Valid: ${FORMATS.join(', ')}`);
      process.exit(1);
    }

    try {
      // Fail fast on a traversal-shaped slug before any network call — the
      // eventual write goes through writeFormat()'s own assertValidSlug too,
      // but rejecting here avoids a pointless fetch for input that could
      // never succeed.
      assertValidSlug(realSlug);
    } catch (err) {
      console.error(`Error: ${(err as Error).message}`);
      process.exit(1);
    }

    try {
      process.stdout.write(`Fetching ${isAgent ? 'agent' : 'skill'} "${realSlug}"... `);
      const meta = await (isAgent ? fetchAgentMeta(realSlug) : fetchSkillMeta(realSlug));
      // Auto-install/deploy creates the gate record (idempotent) so package download succeeds
      if (isAgent) {
        await autoDeployAgent(realSlug);
      } else {
        await autoInstallSkill(realSlug);
      }
      const content = await (isAgent ? fetchAgentPackage(realSlug, apiFormat) : fetchSkillPackage(realSlug, apiFormat));
      process.stdout.write('done\n');

      const outPath = writeToFormat(
        fmt,
        process.cwd(),
        realSlug,
        { name: meta.name, description: meta.description, version: (meta as { version?: string }).version ?? '1.0.0' },
        content
      );

      console.log(`✓ Installed "${meta.name}" → ${outPath}`);
      console.log(`  Format: ${fmt}`);
    } catch (err) {
      console.error(`Error: ${(err as Error).message}`);
      process.exit(1);
    }
  });

program
  .command('run <slug>')
  .description(
    'Run an agent locally in Docker, using your own LLM key (no cloud deploy).\n' +
    '  maindala run agent/<agent-slug>\n\n' +
    '  Server mode (default): serves POST http://localhost:8080/run\n' +
    '  One-shot:              add --input "..." to run once and print the result'
  )
  .option('--provider <provider>', `LLM provider (${PROVIDERS.join('|')})`, 'anthropic')
  .option('--llm-key <key>', 'LLM API key (prefer env: ANTHROPIC_API_KEY etc. — avoids shell history)')
  .option('--model <model>', 'override the LLM model')
  .option('--team <slugs>', 'comma-separated worker agent slugs → run as a team (entry + up to 4 workers)')
  .option('--input <text>', 'one-shot: run once with this input and exit')
  .option('--port <port>', 'host port for server mode', '8080')
  .option('--image <ref>', 'override the agent-runtime image', DEFAULT_IMAGE)
  .option('--detach', 'server mode: run in the background', false)
  .action(async (slug: string, options: {
    provider?: string; llmKey?: string; model?: string; team?: string; input?: string; port?: string; image?: string; detach?: boolean;
  }) => {
    const realSlug = slug.replace(/^agent\//, '');
    const provider = (options.provider ?? 'anthropic') as Provider;
    if (!PROVIDERS.includes(provider)) {
      console.error(`Unknown provider "${provider}". Valid: ${PROVIDERS.join(', ')}`);
      process.exit(1);
    }
    const workerSlugs = (options.team ?? '')
      .split(',').map((s) => s.trim().replace(/^agent\//, '')).filter(Boolean);
    if (workerSlugs.length > MAX_TEAM_AGENTS - 1) {
      console.error(`A team supports at most ${MAX_TEAM_AGENTS - 1} workers (${MAX_TEAM_AGENTS} agents total).`);
      process.exit(1);
    }
    // Validate before it ever reaches Docker/endpoint construction — a
    // non-numeric or out-of-range value would otherwise flow straight into
    // the `-p <port>:8080` docker arg (e.g. "-p NaN:8080") rather than
    // failing with a message that says why.
    // Range/shape rules live in assertValidPort so this and runServer() share
    // one definition; the user-facing message stays here because it names the
    // CLI flag, which the shared helper has no business knowing about.
    const rawPort = options.port ?? '8080';
    const port = /^\d+$/.test(rawPort) ? parseInt(rawPort, 10) : NaN;
    try {
      assertValidPort(port);
    } catch {
      console.error(`Invalid --port "${rawPort}" — must be an integer between 1024 and 65535.`);
      process.exit(1);
    }
    const opts: RunOptions = {
      provider,
      llmKey: options.llmKey,
      model: options.model,
      input: options.input,
      port,
      image: options.image ?? DEFAULT_IMAGE,
      detach: Boolean(options.detach),
    };

    // Fetch one agent's bundle + name through the free deploy access gate.
    const fetchAgent = async (s: string): Promise<{ slug: string; name: string; bundle: string }> => {
      const meta = await fetchAgentMeta(s);
      await autoDeployAgent(s);                  // idempotent, free access gate
      const bundle = await fetchAgentExport(s);
      return { slug: s, name: meta.name, bundle };
    };

    try {
      // Fail early on a missing LLM key, before pulling images / hitting the API.
      resolveLlmKey(opts);

      let payload: Payload;
      let displayName: string;
      if (workerSlugs.length > 0) {
        process.stdout.write(`Fetching team: ${realSlug} + ${workerSlugs.join(', ')}... `);
        const [entry, ...workers] = await Promise.all([realSlug, ...workerSlugs].map(fetchAgent));
        payload = { kind: 'team', teamConfig: assembleTeamConfig(entry!, workers) };
        displayName = `${entry!.name} (team of ${workers.length + 1})`;
      } else {
        process.stdout.write(`Fetching agent "${realSlug}"... `);
        const entry = await fetchAgent(realSlug);
        payload = { kind: 'single', bundle: entry.bundle };
        displayName = entry.name;
      }
      process.stdout.write('done\n');

      if (opts.input !== undefined) {
        await runOneShot(realSlug, displayName, payload, opts);
      } else {
        runServer(realSlug, displayName, payload, opts);
      }
    } catch (err) {
      console.error(`Error: ${(err as Error).message}`);
      process.exit(1);
    }
  });

program
  .command('login <api-key>')
  .description(
    'Save your mAIndala API key.\n' +
    '  mk_ personal key: from https://www.maindala.com/profile\n' +
    '  mt_ free telemetry token: from `maindala tail --signup <email>` (no account needed)'
  )
  .action((apiKey: string) => {
    if (!apiKey.startsWith('mk_') && !apiKey.startsWith('mt_')) {
      console.error('API key must start with "mk_" or "mt_". Get one at https://www.maindala.com/profile, or run `maindala tail --signup <email>`.');
      process.exit(1);
    }
    saveApiKey(apiKey);
    console.log('✓ API key saved to ~/.maindala/config.json');
  });

program
  .command('whoami')
  .description('Show the currently configured API key prefix')
  .action(() => {
    const key = getApiKey();
    if (!key) {
      console.log('No API key configured. Run: maindala login <mk_...>');
    } else {
      console.log(`API key: ${key.slice(0, 11)}...`);
    }
  });

program
  .command('tail [org-slug]')
  .description(
    'Live-tail governed tool calls + A2A delegations. Metadata only — never shows\n' +
    'prompts, tool arguments, or results, only tool/target/decision/latency.\n\n' +
    '  Free, zero-setup tier: `maindala tail --signup you@example.com`\n' +
    '    Mints a free mt_ token (no account/org needed) and starts tailing your\n' +
    '    own agent\'s telemetry immediately — pair with @maindala/agent-guard\'s\n' +
    '    pushToolCallTelemetry(). Ephemeral (short-lived by design): last 500\n' +
    '    events / 1 hour, whichever comes first.\n\n' +
    '  Org-governed tier: `maindala tail <org-slug>`\n' +
    '    Requires an mk_ personal API key belonging to an owner/admin of\n' +
    '    <org-slug> (run `maindala login <mk_...>` first).\n\n' +
    '  Already have an mt_ token saved (`maindala login <mt_...>`)? Just run\n' +
    '  `maindala tail` with no org-slug.'
  )
  .option('--signup <email>', 'mint a free mt_ telemetry token and save it, then start tailing')
  .option('--json', 'emit raw NDJSON instead of colorized lines')
  .option('--filter-decision <decision>', 'only show events with this decision (allow|deny|redact|flag)')
  .option('--filter-tool <tool>', 'only show events for this tool/call_agent name')
  .option('--since <duration>', 'initial lookback window, e.g. 30s, 10m, 2h (default: last 50 events)')
  .action(async (orgSlug: string | undefined, options: { signup?: string; json?: boolean; filterDecision?: string; filterTool?: string; since?: string }) => {
    const { tailActivity, tailFreeStream, signupForTelemetryToken } = await import('./tail.js');
    const tailOptions = {
      json: options.json,
      filterDecision: options.filterDecision,
      filterTool: options.filterTool,
      since: options.since,
    };

    try {
      if (options.signup) {
        const token = await signupForTelemetryToken(options.signup);
        saveApiKey(token);
        console.log(`✓ Free telemetry token saved to ~/.maindala/config.json (${token.slice(0, 11)}...)\n`);
        await tailFreeStream(token, tailOptions);
        return;
      }

      const apiKey = getApiKey();
      if (!apiKey) {
        console.error('No API key configured. Run: maindala login <mk_...> or maindala tail --signup <email>');
        process.exit(1);
      }

      if (apiKey.startsWith('mt_')) {
        await tailFreeStream(apiKey, tailOptions);
        return;
      }

      if (!orgSlug) {
        console.error('An org-slug is required for mk_ keys: maindala tail <org-slug>');
        process.exit(1);
      }
      await tailActivity(orgSlug, apiKey, tailOptions);
    } catch (err) {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  });

program
  .command('init')
  .description(
    'Scaffold @maindala/telemetry into the current project.\n' +
    '  Writes a small example file showing how to push metadata-only tool-call\n' +
    '  events. Requires a token — run `maindala tail --signup <email>` first.'
  )
  .action(async () => {
    const { initProject } = await import('./init.js');
    const result = initProject(getApiKey());
    for (const line of result.lines) console.log(line);
    process.exit(result.exitCode);
  });

program
  .command('verify-pack <directory>')
  .description(
    'Offline-verify a downloaded Compliance Evidence Pack.\n' +
    '  Checks every section file against manifest.json\'s digests and, if present,\n' +
    '  validates the RFC 3161 timestamp token — no mAIndala account or network access\n' +
    '  needed beyond having downloaded the pack\'s files into <directory>.'
  )
  .action(async (directory: string) => {
    const { verifyPack } = await import('./verify-pack.js');
    const result = await verifyPack(directory);
    for (const line of result.lines) console.log(line);
    process.exit(result.exitCode);
  });

program
  .command('scan [path]')
  .description(
    'Discover AI agents and MCP integrations in a local codebase — no account\n' +
    '  or API key needed for the report itself, and it always completes even\n' +
    '  offline. (One unauthenticated lookup per MCP server found is attempted\n' +
    '  against the public catalog for context, not required — see DATA.md for\n' +
    '  the exact per-flag breakdown of what is ever sent, and to whom.)\n\n' +
    '  Detects, in three confidence tiers: agent/LLM dependencies declared in\n' +
    '  package.json/requirements.txt/pyproject.toml/go.mod (high); MCP client\n' +
    '  config or crew/agent definition files (high); source-code patterns like\n' +
    '  StateGraph(/Crew(/new Client( (low — never auto-registered).\n\n' +
    '  `--format sarif --output scan.sarif` emits an OASIS SARIF 2.1.0 report plus\n' +
    '  a sidecar manifest.json (SHA-256 digest) you can sign with your own\n' +
    '  infrastructure — this local artifact is a complete record independent of\n' +
    '  anything pushed to mAIndala. `--timestamp` additionally fetches a free\n' +
    '  RFC 3161 token over that digest from a public Time-Stamp Authority.\n\n' +
    '  `--register --org <slug>` pushes findings into that org\'s governed agent\n' +
    '  registry (requires `maindala login <mk_...>` as a member of the org).\n' +
    '  Metadata only by default — pass --include-definitions to also send file\n' +
    '  content for server-side trust scanning.'
  )
  .option('--json', 'print findings as JSON to stdout (shorthand for --format json)')
  .option('--format <format>', 'table (default) | json | sarif')
  .option('--output <path>', 'write the report to this path instead of stdout (required for sarif)')
  .option('--timestamp', 'fetch an RFC 3161 timestamp token over the manifest digest (requires --format sarif --output)')
  .option('--register', 'push findings into a governed org registry')
  .option('--org <slug>', 'org slug to register into (required with --register)')
  .option('--include-definitions', 'send file content with --register, enabling server-side trust scanning')
  .action(async (scanPath: string | undefined, options: {
    json?: boolean; format?: string; output?: string; timestamp?: boolean;
    register?: boolean; org?: string; includeDefinitions?: boolean;
  }) => {
    const { scanDirectory, toTable, toSarif, toManifest, serializeSarif, writeOutput } = await import('./scan.js');
    const { matchCatalog, registerDiscovered } = await import('./api.js');

    const format = options.format ?? (options.json ? 'json' : 'table');
    if (!['table', 'json', 'sarif'].includes(format)) {
      console.error(`Invalid --format "${format}" — expected table, json, or sarif.`);
      process.exit(1);
    }
    if (options.register && !options.org) {
      console.error('--register requires --org <slug>.');
      process.exit(1);
    }
    if (options.timestamp && format !== 'sarif') {
      console.error('--timestamp requires --format sarif --output <path>.');
      process.exit(1);
    }

    const root = scanPath ?? '.';
    const findings = await scanDirectory({ root, matchCatalog });

    if (format === 'table') {
      for (const line of toTable(findings)) console.log(line);
    } else if (format === 'json') {
      const json = JSON.stringify(findings, null, 2);
      if (options.output) writeOutput(options.output, Buffer.from(json + '\n', 'utf8'));
      else console.log(json);
    } else {
      if (!options.output) {
        console.error('--format sarif requires --output <path>.');
        process.exit(1);
      }
      const sarif = toSarif(findings, pkg.version);
      const sarifBytes = serializeSarif(sarif);
      writeOutput(options.output, sarifBytes);

      const manifest = toManifest(sarifBytes, path.basename(options.output), `maindala@${pkg.version}`);
      if (options.timestamp) {
        const { requestTimestamp } = await import('./tsa-client.js');
        const digestBytes = Buffer.from(manifest.digest, 'hex');
        const token = await requestTimestamp(digestBytes);
        if (token) {
          manifest.timestampToken = token.toString('base64');
          console.log('✓ RFC 3161 timestamp obtained.');
        } else {
          console.log('⚠ Could not obtain an RFC 3161 timestamp (TSA unreachable or declined) — continuing without one.');
        }
      }
      const manifestPath = path.join(path.dirname(options.output), 'manifest.json');
      writeOutput(manifestPath, Buffer.from(JSON.stringify(manifest, null, 2) + '\n', 'utf8'));
      console.log(`✓ Wrote ${options.output} and ${manifestPath} (${findings.length} finding${findings.length === 1 ? '' : 's'}).`);
    }

    if (options.register) {
      const apiKey = getApiKey();
      if (!apiKey) {
        console.error('No API key configured. Run: maindala login <mk_...>');
        process.exit(1);
      }
      const scanRef = `repo:${path.basename(path.resolve(root))}`;
      const payload = findings.map((f) => ({
        sourceRef: f.sourceRef,
        name: f.name,
        platform: f.platform,
        purpose: f.purpose,
        confidence: f.confidence,
        evidence: { tier: f.tier, signal: f.signal, file: f.filePath },
        catalogMatches: f.catalogMatches.map((m) => ({ slug: m.slug, kind: m.kind })),
        definition: options.includeDefinitions ? { file: f.filePath, signal: f.signal } : undefined,
      }));
      try {
        const result = await registerDiscovered(options.org!, scanRef, payload);
        console.log(
          `✓ Registered into "${options.org}": ${result.created} created, ${result.updated} updated, ` +
          `${result.skipped} skipped${result.skipped > 0 ? ` (${JSON.stringify(result.skippedReasons)})` : ''}.`
        );
      } catch (err) {
        console.error(err instanceof Error ? err.message : String(err));
        process.exit(1);
      }
    }
  });

program.parse();
