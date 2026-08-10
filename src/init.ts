// `maindala init` — Free Telemetry Wedge P3. Scaffolds the @maindala/telemetry
// wiring into the current project so "install → tail" is a single guided flow,
// not a blank-page README read. Deliberately light — this writes ONE example
// file, never touches existing project files, and is a no-op if that file
// already exists (idempotent, matches this CLI's existing upsert philosophy).

import fs from 'fs';
import path from 'path';

const EXAMPLE_FILENAME = 'maindala-telemetry.example.ts';

const EXAMPLE_TEMPLATE = `// Example: pushing metadata-only telemetry to your free mAIndala tail.
// Metadata only — never sends prompts, tool arguments, or tool results.
// Run \`maindala tail\` (in another terminal) to watch these live.
import { pushToolCallTelemetry } from '@maindala/telemetry';

const TELEMETRY_TOKEN = process.env.MAINDALA_TELEMETRY_TOKEN!;

export async function afterToolCall(toolName: string, target: string, startedAt: number): Promise<void> {
  await pushToolCallTelemetry(TELEMETRY_TOKEN, {
    kind: 'tool_call',
    toolName,
    target,
    latencyMs: Date.now() - startedAt,
  });
}
`;

export interface InitResult {
  lines: string[];
  exitCode: number;
}

export function initProject(token: string | undefined): InitResult {
  const lines: string[] = [];

  if (!token || !token.startsWith('mt_')) {
    lines.push(token ? 'Your configured key is not a telemetry token (mt_...).' : 'No telemetry token configured yet.');
    lines.push('Run: maindala tail --signup you@example.com');
    lines.push('(mints a free mt_ token, no account needed, and starts tailing immediately)');
    return { lines, exitCode: 1 };
  }

  const targetPath = path.join(process.cwd(), EXAMPLE_FILENAME);
  if (fs.existsSync(targetPath)) {
    lines.push(`${EXAMPLE_FILENAME} already exists here — leaving it as-is.`);
  } else {
    fs.writeFileSync(targetPath, EXAMPLE_TEMPLATE, 'utf8');
    lines.push(`✓ Wrote ${EXAMPLE_FILENAME}`);
  }

  lines.push('');
  lines.push('Next steps:');
  lines.push('  1. npm install @maindala/telemetry');
  // Never echo the full token — it's a live credential, and this line is
  // exactly the kind of thing that ends up in terminal scrollback, a CI
  // log, or a pasted bug report. Same truncation convention as every other
  // key-printing site in this CLI (see `login`'s status output). Point at
  // both possible sources rather than assuming one — the token in scope
  // here could have come from MAINDALA_API_KEY or from a prior `login`/
  // `--signup`, which are the only two places getApiKey() ever reads it.
  lines.push(`  2. export MAINDALA_TELEMETRY_TOKEN=<your token> (${token.slice(0, 11)}... — see your MAINDALA_API_KEY env var, or ~/.maindala/config.json)`);
  lines.push(`  3. Call afterToolCall(...) from ${EXAMPLE_FILENAME} after each tool call`);
  lines.push('  4. maindala tail   (in another terminal, to watch live)');

  return { lines, exitCode: 0 };
}
