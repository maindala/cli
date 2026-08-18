// Real end-to-end tests for the scanner: writes real fixture files to a real
// temp directory and runs scanDirectory()/toSarif()/toManifest() against them
// — no mocked filesystem. Determinism (SAD-D1/§5.1) is tested by actually
// re-running the scan and byte-diffing the serialized SARIF, not by trusting
// the sort function's logic in isolation.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  scanDirectory, toTable, toSarif, toManifest, serializeSarif, sortFindings,
  type ScanFinding, type CatalogMatch,
} from './scan.js';

let root: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'maindala-scan-test-'));
});
afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const full = path.join(root, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
}

describe('Tier 1 — dependency manifests', () => {
  it('detects a known JS package in package.json dependencies', async () => {
    write('package.json', JSON.stringify({ dependencies: { langgraph: '^0.2.1', express: '^4.0.0' } }));
    const findings = await scanDirectory({ root });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.tier).toBe(1);
    expect(findings[0]!.confidence).toBe('high');
    expect(findings[0]!.signal).toBe('langgraph@^0.2.1');
  });

  it('infers a PlatformEnum value for a package that has one (real gap found in manual --register testing)', async () => {
    write('package.json', JSON.stringify({ dependencies: { langgraph: '^0.2.1' } }));
    const findings = await scanDirectory({ root });
    expect(findings[0]!.platform).toBe('langgraph');
  });

  it('leaves platform undefined for a package with no direct PlatformEnum match, rather than guessing', async () => {
    write('package.json', JSON.stringify({ dependencies: { langchain: '^0.1.0' } }));
    const findings = await scanDirectory({ root });
    expect(findings[0]!.platform).toBeUndefined();
  });

  it('does NOT flag an unrelated package.json with no agent/LLM deps (negative control)', async () => {
    write('package.json', JSON.stringify({ dependencies: { express: '^4.0.0', lodash: '^4.17.21' } }));
    const findings = await scanDirectory({ root });
    expect(findings).toHaveLength(0);
  });

  it('detects a known Python package in requirements.txt', async () => {
    write('requirements.txt', 'crewai>=0.30.0\nrequests==2.31.0\n');
    const findings = await scanDirectory({ root });
    expect(findings.map((f) => f.signal)).toContain('crewai');
    expect(findings).toHaveLength(1); // requests must not false-positive
  });

  it('detects a known Python package in pyproject.toml', async () => {
    write('pyproject.toml', '[tool.poetry.dependencies]\npython = "^3.11"\nlangchain = "^0.1.0"\n');
    const findings = await scanDirectory({ root });
    expect(findings.map((f) => f.signal)).toContain('langchain');
  });

  it('detects a keyword-matching go.mod require line', async () => {
    write('go.mod', 'module example.com/foo\n\ngo 1.22\n\nrequire github.com/modelcontextprotocol/go-sdk v0.1.0\n');
    const findings = await scanDirectory({ root });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.tier).toBe(1);
  });
});

describe('Tier 2 — definition / MCP config files', () => {
  it('detects a crew.yaml by filename alone', async () => {
    write('crew.yaml', 'agents:\n  - name: researcher\n');
    const findings = await scanDirectory({ root });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.tier).toBe(2);
  });

  it('detects each server in an .mcp.json mcpServers map, one finding per server', async () => {
    write('.mcp.json', JSON.stringify({
      mcpServers: {
        filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'] },
        remote: { url: 'https://mcp.example.com/sse' },
      },
    }));
    const findings = await scanDirectory({ root });
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.tier === 2)).toBe(true);
    const names = findings.map((f) => f.name).sort();
    expect(names[0]).toContain('filesystem');
    expect(names[1]).toContain('remote');
  });

  it('extracts the package name (not "-y") as the catalog-match candidate', async () => {
    write('.mcp.json', JSON.stringify({
      mcpServers: { fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem'] } },
    }));
    let capturedCandidate = '';
    await scanDirectory({
      root,
      matchCatalog: async (candidate) => { capturedCandidate = candidate; return null; },
    });
    expect(capturedCandidate).toBe('@modelcontextprotocol/server-filesystem');
  });

  it('wires a real catalog match into the finding', async () => {
    write('.mcp.json', JSON.stringify({ mcpServers: { fs: { command: 'npx', args: ['-y', 'known-pkg'] } } }));
    const fakeMatch: CatalogMatch = { slug: 'known-pkg', kind: 'service', trustStatus: 'verified', checksPassed: 5, checksTotal: 5, scannedAt: '2026-08-01T00:00:00Z' };
    const findings = await scanDirectory({ root, matchCatalog: async () => fakeMatch });
    expect(findings[0]!.catalogMatches).toEqual([fakeMatch]);
  });

  it('does not crash on a malformed .mcp.json (invalid JSON)', async () => {
    write('.mcp.json', '{ not valid json');
    const findings = await scanDirectory({ root });
    expect(findings).toHaveLength(0);
  });
});

describe('Tier 3 — source signals (low confidence, watch-it-fail on the exclusion rule)', () => {
  it('flags a real StateGraph( construction at low confidence', async () => {
    write('agent.py', 'from langgraph.graph import StateGraph\ngraph = StateGraph(State)\n');
    const findings = await scanDirectory({ root });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.confidence).toBe('low');
    expect(findings[0]!.tier).toBe(3);
  });

  it('does NOT flag a bare "Agent(" occurrence — deliberately excluded as too generic', async () => {
    // This is the negative control for the exclusion documented in scan.ts:
    // if someone re-adds 'Agent(' to SOURCE_SIGNALS this test starts failing,
    // which is the point — prove the false-positive risk is still avoided.
    write('unrelated.py', 'class Agent(Base):\n    pass\n');
    const findings = await scanDirectory({ root });
    expect(findings).toHaveLength(0);
  });

  it('ignores source files inside node_modules / .git / venv', async () => {
    write('node_modules/pkg/index.js', 'new Client()');
    write('.git/hooks/x.py', 'StateGraph(x)');
    write('venv/lib/x.py', 'Crew(x)');
    const findings = await scanDirectory({ root });
    expect(findings).toHaveLength(0);
  });
});

describe('Determinism (Sec 5.1 — hard requirement)', () => {
  it('scanning the same fixture twice produces byte-identical SARIF', async () => {
    write('package.json', JSON.stringify({ dependencies: { crewai: '1.0.0', langgraph: '2.0.0' } }));
    write('agent.py', 'StateGraph(x)\nnew Client()\n');
    write('.mcp.json', JSON.stringify({ mcpServers: { a: { command: 'x' }, b: { command: 'y' } } }));

    const run1 = serializeSarif(toSarif(await scanDirectory({ root }), '1.0.0'));
    const run2 = serializeSarif(toSarif(await scanDirectory({ root }), '1.0.0'));
    expect(run1.equals(run2)).toBe(true);
  });

  it('a changed file DOES change the digest — proves the artifact is not just stable, it is actually sensitive to content', async () => {
    write('package.json', JSON.stringify({ dependencies: { crewai: '1.0.0' } }));
    const before = serializeSarif(toSarif(await scanDirectory({ root }), '1.0.0'));
    write('package.json', JSON.stringify({ dependencies: { crewai: '2.0.0' } }));
    const after = serializeSarif(toSarif(await scanDirectory({ root }), '1.0.0'));
    expect(before.equals(after)).toBe(false);
  });

  it('contains no absolute filesystem paths anywhere in the SARIF (disclosure rule)', async () => {
    write('package.json', JSON.stringify({ dependencies: { crewai: '1.0.0' } }));
    const sarif = serializeSarif(toSarif(await scanDirectory({ root }), '1.0.0')).toString('utf8');
    expect(sarif).not.toContain(root);
    expect(sarif).not.toMatch(/\/Users\//);
  });

  it('contains no wall-clock timestamp field in the SARIF body', async () => {
    write('package.json', JSON.stringify({ dependencies: { crewai: '1.0.0' } }));
    const sarif = JSON.parse(serializeSarif(toSarif(await scanDirectory({ root }), '1.0.0')).toString('utf8'));
    expect(JSON.stringify(sarif)).not.toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  });

  it('sortFindings order is independent of input order (permutation stability)', () => {
    const a: ScanFinding = { sourceRef: 'r#a', name: 'a', confidence: 'high', tier: 1, filePath: 'a.txt', signal: 'x', catalogMatches: [] };
    const b: ScanFinding = { sourceRef: 'r#b', name: 'b', confidence: 'high', tier: 2, filePath: 'b.txt', signal: 'y', catalogMatches: [] };
    const c: ScanFinding = { sourceRef: 'r#c', name: 'c', confidence: 'low', tier: 3, filePath: 'c.txt', signal: 'z', catalogMatches: [] };
    expect(sortFindings([c, a, b])).toEqual(sortFindings([b, c, a]));
  });
});

describe('SARIF level mapping (Sec 10.6)', () => {
  it('maps tier 1 and 2 to "warning" and tier 3 to "note"', async () => {
    write('package.json', JSON.stringify({ dependencies: { crewai: '1.0.0' } }));
    write('crew.yaml', 'x');
    write('agent.py', 'StateGraph(x)');
    const sarif = JSON.parse(serializeSarif(toSarif(await scanDirectory({ root }), '1.0.0')).toString('utf8'));
    const results = sarif.runs[0].results as { ruleId: string; level: string }[];
    expect(results.find((r) => r.ruleId === 'tier-1')!.level).toBe('warning');
    expect(results.find((r) => r.ruleId === 'tier-2')!.level).toBe('warning');
    expect(results.find((r) => r.ruleId === 'tier-3')!.level).toBe('note');
  });

  it('carries the sourceRef as partialFingerprints.maindalaSourceRef', async () => {
    write('package.json', JSON.stringify({ dependencies: { crewai: '1.0.0' } }));
    const findings = await scanDirectory({ root });
    const sarif = JSON.parse(serializeSarif(toSarif(findings, '1.0.0')).toString('utf8'));
    expect(sarif.runs[0].results[0].partialFingerprints.maindalaSourceRef).toBe(findings[0]!.sourceRef);
  });
});

describe('writeOutput', () => {
  it('creates missing parent directories rather than throwing ENOENT (real bug found in manual testing)', async () => {
    const { writeOutput } = await import('./scan.js');
    const target = path.join(root, 'fresh', 'nested', 'dir', 'scan.sarif');
    expect(() => writeOutput(target, Buffer.from('{}'))).not.toThrow();
    expect(fs.readFileSync(target, 'utf8')).toBe('{}');
  });
});

describe('Manifest (Sec 10.6)', () => {
  it('the manifest digest matches an independently computed SHA-256 of the artifact', async () => {
    const crypto = await import('node:crypto');
    write('package.json', JSON.stringify({ dependencies: { crewai: '1.0.0' } }));
    const sarifBytes = serializeSarif(toSarif(await scanDirectory({ root }), '1.0.0'));
    const manifest = toManifest(sarifBytes, 'scan.sarif', 'maindala@1.0.0');
    const expected = crypto.createHash('sha256').update(sarifBytes).digest('hex');
    expect(manifest.digest).toBe(expected);
    expect(manifest.manifestVersion).toBe(1);
    expect(manifest.digestAlgorithm).toBe('sha256');
    expect(manifest.timestampToken).toBeNull();
  });
});

describe('toTable', () => {
  it('reports "no findings" cleanly on an empty repo', async () => {
    const lines = toTable(await scanDirectory({ root }));
    expect(lines.join('\n')).toContain('No agents or MCP integrations found');
  });

  it('states low-confidence findings are never auto-registered, when any exist', async () => {
    write('agent.py', 'StateGraph(x)');
    const lines = toTable(await scanDirectory({ root }));
    expect(lines.join('\n')).toContain('never auto-registered');
  });
});
