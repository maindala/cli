// Shadow AI discovery: enumerates the AI agents / MCP integrations living in a
// local codebase — dependency manifests, MCP client config files, and (lowest
// confidence) source-code signals — with no account and no network call
// required for the report itself. Optionally pushes findings into a governed
// mAIndala org registry (--register), and/or emits a SARIF 2.1.0 report plus a
// signable digest manifest the caller can hand to their own signing
// infrastructure (cosign, GPG, an in-house TSA) before anything touches
// mAIndala. See the design doc this implements:
// aidlc-docs/design-artifacts/shadow-ai-discovery-p1.md (private monorepo) Sec 5-6, 10.

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { resolveWithinRoot } from './safe-path.js';

// ─── Types ─────────────────────────────────────────────────────────────────

export type Confidence = 'high' | 'medium' | 'low';

export interface CatalogMatch {
  slug: string;
  kind: 'service';
  trustStatus: 'verified' | 'partial' | 'unverified' | null;
  checksPassed: number | null;
  checksTotal: number | null;
  scannedAt: string | null;
}

export interface ScanFinding {
  // Stable per-repo identity: 'repo:<basename>#<relative-file-path>'. Used both
  // as the SARIF partialFingerprint and the ingest API's dedupe key, so a
  // consuming tool and the mAIndala registry converge on the same identity.
  sourceRef: string;
  name: string;
  platform?: string;
  purpose?: string;
  confidence: Confidence;
  tier: 1 | 2 | 3;
  filePath: string;   // relative to the scan root — never absolute (disclosure rule)
  signal: string;      // the concrete evidence string (dependency name, filename, source pattern)
  catalogMatches: CatalogMatch[];
}

export interface ScanOptions {
  root: string;
  matchCatalog?: (candidate: string) => Promise<CatalogMatch | null>;
}

// ─── Directory walk ────────────────────────────────────────────────────────

const IGNORE_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', 'venv', '.venv',
  '__pycache__', '.pytest_cache', 'target', 'vendor', '.turbo', 'coverage',
]);

function walk(root: string, dir: string, out: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // permission error or race — skip silently, this is a best-effort local scan
  }
  for (const entry of entries) {
    if (entry.name.startsWith('.') && entry.name !== '.mcp.json') continue;
    if (IGNORE_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(root, full, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
}

function relFile(root: string, absPath: string): string {
  // Repo-relative, forward-slash always (Windows path.sep would otherwise leak
  // into SARIF locations and break the determinism/cross-platform contract).
  return path.relative(root, absPath).split(path.sep).join('/');
}

// ─── Tier 1 — dependency manifests ─────────────────────────────────────────

// Package/module names that indicate agent-framework or LLM-SDK usage. Matched
// as an exact key (package.json deps) or a whole-word substring (requirements
// lines, go.mod require paths) — never a bare substring of an unrelated name.
const KNOWN_JS_PACKAGES = [
  'langchain', '@langchain/langgraph', 'langgraph', 'crewai', 'autogen',
  'llamaindex', 'llama-index', '@microsoft/semantic-kernel', 'openai',
  '@anthropic-ai/sdk', '@modelcontextprotocol/sdk',
];
const KNOWN_PY_PACKAGES = [
  'langchain', 'langgraph', 'crewai', 'autogen', 'pyautogen', 'llama-index',
  'llama_index', 'semantic-kernel', 'openai', 'anthropic', 'mcp',
];

// Maps a matched dependency name to the ingest API's PlatformEnum where a
// direct correspondence exists ('langgraph', 'crewai', 'openai' — see
// external-agents.ts's PlatformEnum, private monorepo). Anything without a
// direct match (langchain, autogen, llama-index, semantic-kernel, anthropic,
// mcp itself) is left unset and falls back to the ingest API's own 'generic'
// default — inventing a platform value the enum doesn't recognize would just
// get silently normalized away server-side, so there is no upside to guessing.
function inferPlatform(pkgName: string): string | undefined {
  const lower = pkgName.toLowerCase();
  if (lower.includes('langgraph')) return 'langgraph';
  if (lower === 'crewai') return 'crewai';
  if (lower === 'openai') return 'openai';
  return undefined;
}

function scanPackageJson(root: string, filePath: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  let parsed: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return findings; // not valid JSON — not our concern, skip quietly
  }
  const allDeps = { ...(parsed.dependencies ?? {}), ...(parsed.devDependencies ?? {}) };
  const rel = relFile(root, filePath);
  for (const dep of Object.keys(allDeps)) {
    const hit = KNOWN_JS_PACKAGES.find((k) => k.toLowerCase() === dep.toLowerCase());
    if (!hit) continue;
    findings.push({
      sourceRef: `repo:${path.basename(root)}#${rel}`,
      name: `${dep} usage in ${rel}`,
      confidence: 'high',
      tier: 1,
      filePath: rel,
      signal: `${dep}@${allDeps[dep]}`,
      platform: inferPlatform(dep),
      catalogMatches: [],
    });
  }
  return findings;
}

function scanRequirementsOrPyproject(root: string, filePath: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const rel = relFile(root, filePath);
  const content = fs.readFileSync(filePath, 'utf8');
  const seen = new Set<string>();
  for (const line of content.split('\n')) {
    const trimmed = line.trim().toLowerCase();
    if (!trimmed || trimmed.startsWith('#')) continue;
    for (const pkg of KNOWN_PY_PACKAGES) {
      if (seen.has(pkg)) continue;
      // Whole-word-ish match: package name followed by end-of-line, a version
      // specifier, or a quote (pyproject.toml lines look like `"langchain>=0.1"`).
      const re = new RegExp(`(^|["'\\s])${pkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([\\s"'=<>!~]|$)`);
      if (re.test(trimmed)) {
        seen.add(pkg);
        findings.push({
          sourceRef: `repo:${path.basename(root)}#${rel}`,
          name: `${pkg} usage in ${rel}`,
          confidence: 'high',
          tier: 1,
          filePath: rel,
          signal: pkg,
          platform: inferPlatform(pkg),
          catalogMatches: [],
        });
      }
    }
  }
  return findings;
}

function scanGoMod(root: string, filePath: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const rel = relFile(root, filePath);
  const content = fs.readFileSync(filePath, 'utf8');
  const keywords = ['langchain', 'openai', 'anthropic', 'modelcontextprotocol'];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('module ') || trimmed.startsWith('go ')) continue;
    const lower = trimmed.toLowerCase();
    const hit = keywords.find((k) => lower.includes(k));
    if (!hit) continue;
    findings.push({
      sourceRef: `repo:${path.basename(root)}#${rel}`,
      name: `Go module referencing "${hit}" in ${rel}`,
      confidence: 'high',
      tier: 1,
      filePath: rel,
      signal: trimmed,
      catalogMatches: [],
    });
  }
  return findings;
}

// ─── Tier 2 — definition / MCP client config files ─────────────────────────

const TIER2_FILENAMES = new Set([
  'crew.yaml', 'crew.yml', 'agents.yaml', 'agents.yml',
  '.mcp.json', 'mcp.json', 'claude_desktop_config.json',
]);

interface McpServerEntry {
  command?: string;
  args?: string[];
  url?: string;
}

// Extracts a best-effort "catalog candidate" string (an npm/pip package name
// or a hostname) from one entry of an MCP client config's `mcpServers` map —
// used for §3.1 catalog matching, not for the finding's identity.
function extractCatalogCandidate(entry: McpServerEntry): string | null {
  if (entry.url) {
    try { return new URL(entry.url).hostname; } catch { /* fall through */ }
  }
  const args = entry.args ?? [];
  // Typical shapes: `npx -y @scope/pkg`, `uvx pkg-name`, `python -m pkg_name`.
  for (const a of args) {
    if (a === '-y' || a === '-m' || a.startsWith('-')) continue;
    if (/^[\w@][\w./-]*$/.test(a)) return a;
  }
  return entry.command ?? null;
}

async function scanMcpConfig(root: string, filePath: string, opts: ScanOptions): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const rel = relFile(root, filePath);
  let parsed: { mcpServers?: Record<string, McpServerEntry> };
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return findings;
  }
  const servers = parsed.mcpServers ?? {};
  for (const [serverName, entry] of Object.entries(servers)) {
    const candidate = extractCatalogCandidate(entry);
    let catalogMatches: CatalogMatch[] = [];
    if (candidate && opts.matchCatalog) {
      const match = await opts.matchCatalog(candidate);
      if (match) catalogMatches = [match];
    }
    findings.push({
      sourceRef: `repo:${path.basename(root)}#${rel}::${serverName}`,
      name: `MCP server "${serverName}" in ${rel}`,
      confidence: 'high',
      tier: 2,
      filePath: rel,
      signal: candidate ?? serverName,
      catalogMatches,
    });
  }
  return findings;
}

function scanCrewOrAgentsYaml(root: string, filePath: string): ScanFinding[] {
  // Deliberately filename-only detection, no YAML parsing — a dependency-free
  // CLI shouldn't take on a YAML parser for a tier-2 filename signal alone;
  // the file's mere presence at a conventional name is the evidence.
  const rel = relFile(root, filePath);
  return [{
    sourceRef: `repo:${path.basename(root)}#${rel}`,
    name: `Agent/crew definition file: ${rel}`,
    confidence: 'high',
    tier: 2,
    filePath: rel,
    signal: path.basename(filePath),
    catalogMatches: [],
  }];
}

// ─── Tier 3 — source-code signals (lowest precision) ───────────────────────

const SOURCE_EXTENSIONS = new Set(['.py', '.js', '.ts', '.mjs', '.cjs']);
const SOURCE_SIGNALS = [
  'StateGraph(', 'Crew(', 'ChatOpenAI(', 'stdio_client(', 'ClientSession(',
  // 'Agent(' is intentionally excluded from the plain-name list — it is too
  // common a generic identifier (see the design doc's SAD-2 discussion of
  // false-positive risk) to fire without a co-occurring, more specific
  // signal; construction of an MCP SDK Client is a more precise proxy.
  'new Client(',
];

function scanSourceFile(root: string, filePath: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const rel = relFile(root, filePath);
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return findings;
  }
  for (const signal of SOURCE_SIGNALS) {
    if (!content.includes(signal)) continue;
    findings.push({
      sourceRef: `repo:${path.basename(root)}#${rel}::${signal}`,
      name: `Source signal "${signal}" in ${rel}`,
      confidence: 'low',
      tier: 3,
      filePath: rel,
      signal,
      catalogMatches: [],
    });
  }
  return findings;
}

// ─── Top-level scan ─────────────────────────────────────────────────────────

export async function scanDirectory(opts: ScanOptions): Promise<ScanFinding[]> {
  const root = path.resolve(opts.root);
  const files: string[] = [];
  walk(root, root, files);

  const findings: ScanFinding[] = [];
  for (const file of files) {
    const base = path.basename(file);
    if (base === 'package.json') {
      findings.push(...scanPackageJson(root, file));
    } else if (base === 'requirements.txt' || base === 'pyproject.toml') {
      findings.push(...scanRequirementsOrPyproject(root, file));
    } else if (base === 'go.mod') {
      findings.push(...scanGoMod(root, file));
    } else if (TIER2_FILENAMES.has(base)) {
      if (base.endsWith('.json')) {
        findings.push(...await scanMcpConfig(root, file, opts));
      } else {
        findings.push(...scanCrewOrAgentsYaml(root, file));
      }
    } else if (SOURCE_EXTENSIONS.has(path.extname(base))) {
      findings.push(...scanSourceFile(root, file));
    }
  }

  // Deterministic order: path, then tier, then signal — the same ordering
  // toSarif() re-derives independently, so callers of scanDirectory() and
  // toSarif() never observe two different orderings of the same findings.
  return sortFindings(findings);
}

export function sortFindings(findings: ScanFinding[]): ScanFinding[] {
  return [...findings].sort((a, b) =>
    a.filePath.localeCompare(b.filePath) ||
    a.tier - b.tier ||
    a.signal.localeCompare(b.signal) ||
    a.sourceRef.localeCompare(b.sourceRef));
}

// ─── Output: human-readable table ──────────────────────────────────────────

export function toTable(findings: ScanFinding[]): string[] {
  if (findings.length === 0) return ['No agents or MCP integrations found.'];
  const lines: string[] = [];
  const byTier: Record<1 | 2 | 3, ScanFinding[]> = { 1: [], 2: [], 3: [] };
  for (const f of findings) byTier[f.tier].push(f);

  const tierLabel = { 1: 'Dependency manifests', 2: 'Definition / config files', 3: 'Source signals (low confidence)' };
  for (const tier of [1, 2, 3] as const) {
    if (byTier[tier].length === 0) continue;
    lines.push(`\n${tierLabel[tier]}:`);
    for (const f of byTier[tier]) {
      let line = `  [${f.confidence}] ${f.name}`;
      for (const m of f.catalogMatches) {
        const checks = m.checksTotal !== null ? ` ${m.checksPassed}/${m.checksTotal} checks` : '';
        const status = m.trustStatus ? m.trustStatus[0]!.toUpperCase() + m.trustStatus.slice(1) : 'not yet scanned';
        line += `\n      catalog match: ${m.slug} — ${status}${checks}`;
      }
      lines.push(line);
    }
  }
  lines.push(
    '',
    `${findings.length} finding${findings.length === 1 ? '' : 's'} ` +
    `(${byTier[1].length} high-confidence, ${byTier[2].length} definition-file, ${byTier[3].length} low-confidence source signal${byTier[3].length === 1 ? '' : 's'}).`,
  );
  if (byTier[3].length > 0) {
    lines.push('Low-confidence findings are never auto-registered, even with --register.');
  }
  return lines;
}

// ─── Output: SARIF 2.1.0 (deterministic) ───────────────────────────────────

const SARIF_LEVEL: Record<1 | 2 | 3, 'warning' | 'note'> = { 1: 'warning', 2: 'warning', 3: 'note' };

export function toSarif(findings: ScanFinding[], toolVersion: string): unknown {
  const sorted = sortFindings(findings);
  const ruleIds = [...new Set(sorted.map((f) => `tier-${f.tier}`))].sort();

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'maindala-scan',
          version: toolVersion,
          informationUri: 'https://github.com/maindala/cli',
          rules: ruleIds.map((id) => ({
            id,
            name: id === 'tier-1' ? 'DependencyManifest' : id === 'tier-2' ? 'DefinitionFile' : 'SourceSignal',
            shortDescription: { text: id === 'tier-1' ? 'Agent/LLM dependency declared in a manifest file' : id === 'tier-2' ? 'Agent or MCP client definition/config file present' : 'Low-confidence source-code pattern suggestive of agent/LLM usage' },
          })),
        },
      },
      // No wall-clock timestamp anywhere in this object — invocations/*
      // deliberately omitted; run metadata lives only in the sidecar manifest,
      // per the design doc's determinism requirement (Sec 5.1).
      results: sorted.map((f) => ({
        ruleId: `tier-${f.tier}`,
        level: SARIF_LEVEL[f.tier],
        message: { text: f.name },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.filePath },
          },
        }],
        partialFingerprints: {
          maindalaSourceRef: f.sourceRef,
        },
        properties: {
          confidence: f.confidence,
          signal: f.signal,
          ...(f.catalogMatches.length > 0 ? { catalogMatches: f.catalogMatches } : {}),
        },
      })),
    }],
  };
}

// ─── Output: signable digest manifest ──────────────────────────────────────

export interface ScanManifest {
  manifestVersion: 1;
  artifact: string;
  digestAlgorithm: 'sha256';
  digest: string;
  generatedAt: string;
  toolVersion: string;
  timestampToken: string | null;
}

export function toManifest(sarifBytes: Buffer, artifactName: string, toolVersion: string): ScanManifest {
  return {
    manifestVersion: 1,
    artifact: artifactName,
    digestAlgorithm: 'sha256',
    digest: crypto.createHash('sha256').update(sarifBytes).digest('hex'),
    generatedAt: new Date().toISOString(), // metadata only — not part of the signed SARIF body
    toolVersion,
    timestampToken: null,
  };
}

// Canonical, deterministic JSON serialization for the SARIF artifact — plain
// key order as constructed above (all object literals here use a fixed key
// order, never derived from Map/Set/object-key iteration over scan input) plus
// 2-space indent. sortFindings() upstream is what actually makes re-runs
// byte-identical; this just fixes the print format.
export function serializeSarif(sarif: unknown): Buffer {
  return Buffer.from(JSON.stringify(sarif, null, 2) + '\n', 'utf8');
}

// ─── Safe file output ───────────────────────────────────────────────────────

// Writes `content` to `outputPath`, confined to the caller's cwd unless
// `outputPath` is itself absolute (a user typing --output /tmp/x.sarif on
// their own command line is trusted input, unlike a filename sourced from
// remote data — see safe-path.ts's header comment on this exact distinction).
export function writeOutput(outputPath: string, content: Buffer): void {
  if (path.isAbsolute(outputPath)) {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, content);
    return;
  }
  const resolved = resolveWithinRoot(process.cwd(), outputPath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  fs.writeFileSync(resolved, content);
}
