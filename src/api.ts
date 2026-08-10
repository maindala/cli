import fs from 'fs';
import os from 'os';
import path from 'path';

// Overridable via MAINDALA_CATALOG_URL so a future URL rotation doesn't
// require every installed copy of this CLI to be upgraded before it works.
const BASE_URL = process.env['MAINDALA_CATALOG_URL'] ?? 'https://api.maindala.com';
const CONFIG_PATH = path.join(os.homedir(), '.maindala', 'config.json');

function getApiKey(): string | undefined {
  const envKey = process.env['MAINDALA_API_KEY'];
  if (envKey) return envKey;
  try {
    const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
    const cfg = JSON.parse(raw) as { apiKey?: string };
    return cfg.apiKey;
  } catch {
    return undefined;
  }
}

async function apiFetch(urlPath: string, apiKey?: string, method = 'GET'): Promise<Response> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
  const res = await fetch(`${BASE_URL}${urlPath}`, { method, headers });
  return res;
}

export interface SkillMeta {
  name: string;
  slug: string;
  description: string;
  version: string;
  category?: string;
}

export interface AgentMeta {
  name: string;
  slug: string;
  description: string;
  version: string;
  category?: string;
}

export async function fetchSkillMeta(slug: string): Promise<SkillMeta> {
  const res = await apiFetch(`/skills/${slug}`);
  if (!res.ok) {
    if (res.status === 404) throw new Error(`Skill "${slug}" not found.`);
    throw new Error(`Failed to fetch skill metadata: ${res.status}`);
  }
  return res.json() as Promise<SkillMeta>;
}

export async function fetchAgentMeta(slug: string): Promise<AgentMeta> {
  const res = await apiFetch(`/agents/${slug}`);
  if (!res.ok) {
    if (res.status === 404) throw new Error(`Agent "${slug}" not found.`);
    throw new Error(`Failed to fetch agent metadata: ${res.status}`);
  }
  return res.json() as Promise<AgentMeta>;
}

export async function autoInstallSkill(slug: string): Promise<void> {
  const apiKey = getApiKey();
  if (!apiKey) return;
  await apiFetch(`/skills/${slug}/install`, apiKey, 'POST');
}

export async function autoDeployAgent(slug: string): Promise<void> {
  const apiKey = getApiKey();
  if (!apiKey) return;
  await apiFetch(`/agents/${slug}/deploy`, apiKey, 'POST');
}

export async function fetchSkillPackage(slug: string, format: string): Promise<string> {
  const apiKey = getApiKey();
  if (!apiKey) {
    throw new Error(
      'Authentication required to download skill packages.\n' +
      'Set MAINDALA_API_KEY env var or run: maindala login'
    );
  }
  const res = await apiFetch(`/skills/${slug}/package?format=${format}`, apiKey);
  if (!res.ok) {
    if (res.status === 401 || res.status === 403) {
      throw new Error('Invalid or missing API key. Get one at https://www.maindala.com/profile');
    }
    if (res.status === 404) throw new Error(`Skill "${slug}" not found or not yet installed.`);
    throw new Error(`Failed to download skill package: ${res.status}`);
  }
  return res.text();
}

export async function fetchAgentPackage(slug: string, format: string): Promise<string> {
  const apiKey = getApiKey();
  if (!apiKey) {
    throw new Error(
      'Authentication required to download agent packages.\n' +
      'Set MAINDALA_API_KEY env var or run: maindala login'
    );
  }
  const res = await apiFetch(`/agents/${slug}/package?format=${format}`, apiKey);
  if (!res.ok) {
    if (res.status === 401 || res.status === 403) {
      throw new Error('Invalid or missing API key. Get one at https://www.maindala.com/profile');
    }
    if (res.status === 404) throw new Error(`Agent "${slug}" not found or not yet installed.`);
    throw new Error(`Failed to download agent package: ${res.status}`);
  }
  return res.text();
}

// Fetch the deployable agent bundle (nodes + routes + prompts) as a JSON string,
// ready to pass to the agent-runtime as AGENT_BUNDLE. Requires a deploy record,
// so callers should autoDeployAgent() first (idempotent, free access gate).
export async function fetchAgentExport(slug: string): Promise<string> {
  const apiKey = getApiKey();
  if (!apiKey) {
    throw new Error(
      'Authentication required to run an agent.\n' +
      'Set MAINDALA_API_KEY env var or run: maindala login'
    );
  }
  const res = await apiFetch(`/agents/${slug}/export`, apiKey);
  if (!res.ok) {
    if (res.status === 401) throw new Error('Invalid or missing API key. Get one at https://www.maindala.com/profile');
    if (res.status === 403) throw new Error(`Could not access the bundle for "${slug}". Is the agent public or owned by you?`);
    if (res.status === 404) throw new Error(`Agent "${slug}" not found.`);
    throw new Error(`Failed to fetch agent bundle: ${res.status}`);
  }
  return res.text();
}

export function saveApiKey(apiKey: string): void {
  const dir = path.join(os.homedir(), '.maindala');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify({ apiKey }, null, 2), { mode: 0o600 });
}

export { getApiKey };
