// Local agent runner: pulls the public agent-runtime image and runs a fetched
// agent bundle on the user's machine with their own LLM key (no Cloud Run, no
// platform LLM cost). Secrets (bundle + LLM key) are passed via the child env and
// referenced by name in docker args, so they never appear in argv / `ps` output.

import { spawn, spawnSync } from 'child_process';
import path from 'path';
import { resolveWithinRoot, assertValidPort } from './safe-path.js';

export type Provider = 'anthropic' | 'openai' | 'gemini' | 'xai';
export const PROVIDERS: Provider[] = ['anthropic', 'openai', 'gemini', 'xai'];

// Runtime image the CLI is built against — bump alongside agent-runtime releases
// so local behavior matches what the catalog/runtime expect.
const RUNTIME_IMAGE_TAG = '2.6.7';
export const DEFAULT_IMAGE = `us-west1-docker.pkg.dev/maindala-prod/agent-runtime/agent-runtime:${RUNTIME_IMAGE_TAG}`;

// Provider → conventional env var holding that provider's API key.
const KEY_ENV: Record<Provider, string> = {
  anthropic: 'ANTHROPIC_API_KEY',
  openai: 'OPENAI_API_KEY',
  gemini: 'GEMINI_API_KEY',
  xai: 'XAI_API_KEY',
};

export interface RunOptions {
  provider: Provider;
  llmKey?: string;
  model?: string;
  input?: string; // present → one-shot mode
  port: number;
  image: string;
  detach: boolean;
}

// What gets handed to the runtime: a single agent (AGENT_BUNDLE) or a team
// (TEAM_CONFIG). Both are JSON strings, set in the child env (never argv).
export type Payload =
  | { kind: 'single'; bundle: string }
  | { kind: 'team'; teamConfig: string };

// Max agents in a team (entry + 4 workers) — matches the platform's team cap.
export const MAX_TEAM_AGENTS = 5;

// Assemble a TEAM_CONFIG identical to the platform's own deploy pipeline: entry first, then
// workers, each carrying its parsed bundle. `bundles` are raw JSON strings.
export function assembleTeamConfig(
  entry: { slug: string; name: string; bundle: string },
  workers: Array<{ slug: string; name: string; bundle: string }>,
): string {
  return JSON.stringify({
    entryAgentSlug: entry.slug,
    agents: [
      { slug: entry.slug, name: entry.name, role: 'entry', bundle: JSON.parse(entry.bundle) },
      ...workers.map((w) => ({ slug: w.slug, name: w.name, role: 'worker', bundle: JSON.parse(w.bundle) })),
    ],
  });
}

// Resolve the LLM key without ever sending it to the platform:
// --llm-key → provider env (e.g. ANTHROPIC_API_KEY) → generic MAINDALA_LLM_KEY.
export function resolveLlmKey(opts: RunOptions): string {
  const key = opts.llmKey ?? process.env[KEY_ENV[opts.provider]] ?? process.env['MAINDALA_LLM_KEY'];
  if (!key) {
    throw new Error(`No LLM API key for provider "${opts.provider}". Set ${KEY_ENV[opts.provider]} (or MAINDALA_LLM_KEY), or pass --llm-key.`);
  }
  return key;
}

// Fail fast with an actionable message when Docker isn't usable.
export function preflightDocker(): void {
  const r = spawnSync('docker', ['info'], { stdio: 'ignore' });
  if (r.error || r.status !== 0) {
    throw new Error(
      'Docker is required for `maindala run` — install Docker Desktop and make sure it is running.\n' +
      '(For a prompt-only install into your coding tool, use `maindala install agent/<slug>` instead.)'
    );
  }
}

// Pull the runtime image if it isn't already present locally.
function ensureImage(image: string): void {
  const has = spawnSync('docker', ['image', 'inspect', image], { stdio: 'ignore' });
  if (has.status !== 0) {
    process.stdout.write(`Pulling runtime image ${image} ...\n`);
    const pull = spawnSync('docker', ['pull', image], { stdio: 'inherit' });
    if (pull.status !== 0) throw new Error(`Failed to pull runtime image ${image}`);
  }
}

// Child env carrying the secrets; docker args reference these by name only.
function runtimeEnv(payload: Payload, llmKey: string, opts: RunOptions): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    LLM_PROVIDER: opts.provider,
    LLM_API_KEY: llmKey,
  };
  if (payload.kind === 'team') env['TEAM_CONFIG'] = payload.teamConfig;
  else env['AGENT_BUNDLE'] = payload.bundle;
  if (opts.model) env['LLM_MODEL'] = opts.model;
  return env;
}

function passThroughEnvArgs(payload: Payload, opts: RunOptions): string[] {
  const args = ['-e', payload.kind === 'team' ? 'TEAM_CONFIG' : 'AGENT_BUNDLE', '-e', 'LLM_PROVIDER', '-e', 'LLM_API_KEY'];
  if (opts.model) args.push('-e', 'LLM_MODEL');
  return args;
}

// ── Server mode: long-running container, logs streamed, Ctrl-C stops it ──────
export function runServer(slug: string, agentName: string, payload: Payload, opts: RunOptions): void {
  // Validated here, not only at the CLI entry point: opts.port is interpolated
  // into the `-p <port>:8080` docker argument below, and this function is
  // exported, so it must not depend on its caller having checked first.
  // (runOneShot needs no equivalent — it lets Docker pick a free host port and
  // never interpolates a caller-supplied one.)
  assertValidPort(opts.port);
  preflightDocker();
  ensureImage(opts.image);
  const llmKey = resolveLlmKey(opts);
  const name = `maindala-${slug}`.replace(/[^a-zA-Z0-9_.-]/g, '-');

  // Clear any stale container with the same name.
  spawnSync('docker', ['rm', '-f', name], { stdio: 'ignore' });

  const args = [
    'run', opts.detach ? '-d' : '--rm', '--name', name,
    '-p', `${opts.port}:8080`,
    ...passThroughEnvArgs(payload, opts),
    opts.image,
  ];

  const env = runtimeEnv(payload, llmKey, opts);
  console.log(`\n▶ Running "${agentName}" locally`);
  console.log(`  Endpoint: http://localhost:${opts.port}/run`);
  console.log(`  Try:      curl -s localhost:${opts.port}/run -H 'content-type: application/json' -d '{"input":"hello"}'`);

  if (opts.detach) {
    const r = spawnSync('docker', args, { env, stdio: 'inherit' });
    if (r.status !== 0) throw new Error('Failed to start container');
    console.log(`  Detached. Stop with: docker rm -f ${name}\n`);
    return;
  }

  console.log('  Press Ctrl-C to stop.\n');
  const child = spawn('docker', args, { env, stdio: 'inherit' });
  // Forward Ctrl-C to stop + clean up the container.
  const stop = () => { spawnSync('docker', ['stop', name], { stdio: 'ignore' }); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  child.on('exit', (code) => process.exit(code ?? 0));
}

// ── One-shot mode: start, wait for health, POST /run once, print, tear down ──
export async function runOneShot(slug: string, agentName: string, payload: Payload, opts: RunOptions): Promise<void> {
  preflightDocker();
  ensureImage(opts.image);
  const llmKey = resolveLlmKey(opts);
  const name = `maindala-${slug}-oneshot-${Date.now()}`.replace(/[^a-zA-Z0-9_.-]/g, '-');
  const env = runtimeEnv(payload, llmKey, opts);

  // Let Docker pick a free host port to avoid conflicts.
  const startArgs = ['run', '-d', '--name', name, '-p', '0:8080', ...passThroughEnvArgs(payload, opts), opts.image];
  const start = spawnSync('docker', startArgs, { env, stdio: ['ignore', 'ignore', 'inherit'] });
  if (start.status !== 0) throw new Error('Failed to start container');

  const cleanup = () => spawnSync('docker', ['rm', '-f', name], { stdio: 'ignore' });
  try {
    // Resolve the mapped host port.
    const portOut = spawnSync('docker', ['port', name, '8080'], { encoding: 'utf8' });
    const hostPort = (portOut.stdout || '').trim().split(':').pop();
    if (!hostPort) throw new Error('Could not resolve container port');
    const base = `http://localhost:${hostPort}`;

    process.stdout.write(`Starting "${agentName}" ... `);
    await waitForHealth(base, 40);
    process.stdout.write('ready\n');

    const res = await fetch(`${base}/run`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ input: opts.input }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`Run failed (${res.status}): ${body.slice(0, 300)}`);
    }
    const result = await res.json() as { output?: string; files?: Array<{ filename: string; content?: string }> };
    console.log('\n' + (result.output ?? '(no output)'));
    // Write any inline file outputs to the cwd. `filename` comes from the
    // agent runtime's JSON response — the runtime executes agent code the
    // user chose to run, but treat its output as untrusted input all the
    // same: a malicious or compromised agent must not be able to write
    // outside the working directory it was invoked from.
    for (const f of result.files ?? []) {
      if (f.content) {
        let safePath: string;
        try {
          safePath = resolveWithinRoot(process.cwd(), f.filename);
        } catch (err) {
          console.error(`\n[skipped unsafe file result "${f.filename}": ${(err as Error).message}]`);
          continue;
        }
        const fs = await import('fs');
        fs.mkdirSync(path.dirname(safePath), { recursive: true });
        fs.writeFileSync(safePath, Buffer.from(f.content, 'base64'));
        console.log(`\n[saved file: ${path.relative(process.cwd(), safePath)}]`);
      }
    }
  } finally {
    cleanup();
  }
}

// Poll GET /health until the runtime is up (or give up after `tries` × 500ms).
async function waitForHealth(base: string, tries: number): Promise<void> {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(`${base}/health`, { signal: AbortSignal.timeout(2000) });
      if (r.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('Agent runtime did not become healthy in time. Check `docker logs`.');
}
