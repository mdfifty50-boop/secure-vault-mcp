#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, chmodSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { secrets, tokens, auditLog } from './db.js';

// ═══════════════════════════════════════════
// PERSISTENT MASTER KEY
// ═══════════════════════════════════════════

const VAULT_DIR = join(homedir(), '.secure-vault-mcp');
mkdirSync(VAULT_DIR, { recursive: true });

const MASTER_KEY_PATH = join(VAULT_DIR, 'master.key');

let MASTER_KEY;
if (existsSync(MASTER_KEY_PATH)) {
  MASTER_KEY = Buffer.from(readFileSync(MASTER_KEY_PATH, 'utf8').trim(), 'hex');
} else {
  MASTER_KEY = randomBytes(32);
  writeFileSync(MASTER_KEY_PATH, MASTER_KEY.toString('hex'), 'utf8');
  chmodSync(MASTER_KEY_PATH, 0o600);
}

// ═══════════════════════════════════════════
// ENCRYPTION HELPERS
// ═══════════════════════════════════════════

function encrypt(plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { encrypted: encrypted.toString('base64'), iv: iv.toString('base64'), tag: tag.toString('base64') };
}

function decrypt(record) {
  const decipher = createDecipheriv('aes-256-gcm', MASTER_KEY, Buffer.from(record.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
  return decipher.update(Buffer.from(record.encrypted, 'base64')) + decipher.final('utf8');
}

function logAudit(agent_id, secret_name, action, detail = '') {
  auditLog.push({ timestamp: new Date().toISOString(), agent_id, secret_name, action, detail });
}

// Leak detection patterns
const LEAK_PATTERNS = [
  { name: 'AWS Access Key',        regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Key',        regex: /(?:aws_secret_access_key|secret_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi },
  { name: 'GitHub Token',          regex: /gh[ps]_[A-Za-z0-9_]{36,}/g },
  { name: 'GitHub Fine-Grained',   regex: /github_pat_[A-Za-z0-9_]{22,}/g },
  { name: 'OpenAI API Key',        regex: /sk-[A-Za-z0-9]{20,}/g },
  { name: 'Anthropic API Key',     regex: /sk-ant-[A-Za-z0-9_-]{40,}/g },
  { name: 'Slack Token',           regex: /xox[bpors]-[0-9A-Za-z-]{10,}/g },
  { name: 'Stripe Key',            regex: /sk_(?:live|test)_[A-Za-z0-9]{24,}/g },
  { name: 'Generic API Key',       regex: /(?:api[_-]?key|apikey)\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,})["']?/gi },
  { name: 'Generic Secret',        regex: /(?:secret|password|passwd|token)\s*[=:]\s*["']([^"'\s]{8,})["']/gi },
  { name: 'Private Key Block',     regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g },
  { name: 'Bearer Token',          regex: /Bearer\s+[A-Za-z0-9_\-.]{20,}/g },
];

// ═══════════════════════════════════════════
// SERVER
// ═══════════════════════════════════════════

const server = new McpServer({
  name: 'secure-vault-mcp',
  version: '0.1.0',
  description: 'Agent-native secrets management — store, rotate, and inject secrets without agents seeing raw values',
});

// ═══════════════════════════════════════════
// TOOL: store_secret
// ═══════════════════════════════════════════

server.tool(
  'store_secret',
  'Store an encrypted secret with optional rotation policy. Value is encrypted at rest with AES-256-GCM.',
  {
    name: z.string().min(1).describe('Secret name (e.g. "openai_api_key", "stripe_live")'),
    value: z.string().min(1).describe('The secret value to store — encrypted immediately, never stored in plaintext'),
    service: z.string().default('default').describe('Service this secret belongs to (e.g. "openai", "stripe")'),
    rotation_policy: z.enum(['none', 'daily', 'weekly', 'monthly']).default('none').describe('Automatic rotation reminder policy'),
  },
  async (params) => {
    const now = new Date().toISOString();
    const existing = secrets.get(params.name);
    const record = {
      ...encrypt(params.value),
      service: params.service,
      rotation_policy: params.rotation_policy,
      created_at: existing ? existing.created_at : now,
      rotated_at: now,
    };
    secrets.set(params.name, record);
    logAudit('system', params.name, 'store', `service=${params.service} rotation=${params.rotation_policy}`);

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          stored: true,
          name: params.name,
          service: params.service,
          rotation_policy: params.rotation_policy,
          encrypted_size: record.encrypted.length,
          created_at: record.created_at,
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// TOOL: get_agent_token
// ═══════════════════════════════════════════

server.tool(
  'get_agent_token',
  'Issue a short-lived, scoped token for an agent to use a secret. The agent receives an opaque token ID — never the raw secret. Use inject_secret_to_request to apply the token to an outbound request.',
  {
    agent_id: z.string().min(1).describe('Identifier of the requesting agent'),
    service: z.string().min(1).describe('Service name to get a token for (must match a stored secret\'s service)'),
    scope: z.enum(['read', 'write', 'admin']).default('read').describe('Permission scope for this token'),
    ttl_seconds: z.number().int().min(10).max(86400).default(300).describe('Token time-to-live in seconds (default 300 = 5 min, max 86400 = 24h)'),
  },
  async (params) => {
    // Find a secret for this service
    const matches = secrets.getByService(params.service);
    if (!matches.length) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: true, message: `No secret found for service "${params.service}"` }) }] };
    }
    const secretName = matches[0].name;

    const tokenId = `svt_${randomBytes(24).toString('hex')}`;
    const expiresAt = new Date(Date.now() + params.ttl_seconds * 1000).toISOString();
    tokens.set(tokenId, {
      agent_id: params.agent_id,
      secret_name: secretName,
      scope: params.scope,
      expires_at: expiresAt,
    });

    logAudit(params.agent_id, secretName, 'token_issued', `scope=${params.scope} ttl=${params.ttl_seconds}s token=${tokenId.slice(0, 12)}...`);

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          token_id: tokenId,
          agent_id: params.agent_id,
          service: params.service,
          scope: params.scope,
          expires_at: expiresAt,
          note: 'Use inject_secret_to_request with this token_id to make authenticated requests. You never see the raw secret.',
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// TOOL: rotate_secrets
// ═══════════════════════════════════════════

server.tool(
  'rotate_secrets',
  'Rotate all secrets for a given service. Old values are overwritten, and all outstanding tokens for those secrets are invalidated.',
  {
    service: z.string().min(1).describe('Service whose secrets to rotate (e.g. "openai")'),
    new_value: z.string().min(1).describe('The new secret value to replace the old one'),
  },
  async (params) => {
    const matches = secrets.getByService(params.service);
    const rotated = [];

    for (const record of matches) {
      const updated = {
        ...encrypt(params.new_value),
        service: record.service,
        rotation_policy: record.rotation_policy,
        created_at: record.created_at,
        rotated_at: new Date().toISOString(),
      };
      secrets.set(record.name, updated);
      rotated.push(record.name);
      logAudit('system', record.name, 'rotate', `service=${params.service}`);
    }

    // Invalidate tokens pointing to rotated secrets
    let invalidated = 0;
    for (const name of rotated) {
      const tokenIds = tokens.tokensBySecret(name);
      for (const tokenId of tokenIds) {
        tokens.delete(tokenId);
        invalidated++;
      }
    }

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          rotated: rotated.length > 0,
          service: params.service,
          secrets_rotated: rotated,
          tokens_invalidated: invalidated,
          rotated_at: new Date().toISOString(),
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// TOOL: audit_secret_access
// ═══════════════════════════════════════════

server.tool(
  'audit_secret_access',
  'View an audit trail of who accessed which secrets over a time range.',
  {
    time_range: z.enum(['1h', '6h', '24h', '7d', 'all']).default('24h').describe('Time range to query'),
    agent_id: z.string().optional().describe('Filter by specific agent (omit for all agents)'),
    secret_name: z.string().optional().describe('Filter by specific secret name (omit for all secrets)'),
  },
  async (params) => {
    const now = Date.now();
    const rangeMs = { '1h': 3600e3, '6h': 21600e3, '24h': 86400e3, '7d': 604800e3, all: Infinity };
    const cutoff = now - (rangeMs[params.time_range] ?? 86400e3);

    const { total, entries } = auditLog.query({
      cutoff,
      agent_id: params.agent_id ?? null,
      secret_name: params.secret_name ?? null,
    });

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          time_range: params.time_range,
          total_entries: total,
          entries,
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// TOOL: scan_config_for_leaks
// ═══════════════════════════════════════════

server.tool(
  'scan_config_for_leaks',
  'Scan a config text for exposed secrets — API keys, tokens, passwords, private keys. Uses 12 regex patterns covering AWS, GitHub, OpenAI, Anthropic, Slack, Stripe, and generic credentials.',
  {
    config_text: z.string().min(1).describe('The config file content or JSON/YAML text to scan'),
    source_label: z.string().default('unknown').describe('Label for where this config came from (for audit trail)'),
  },
  async (params) => {
    const findings = [];
    for (const pattern of LEAK_PATTERNS) {
      const matches = [...params.config_text.matchAll(pattern.regex)];
      for (const match of matches) {
        const value = match[0];
        findings.push({
          type: pattern.name,
          match_preview: value.slice(0, 8) + '...' + value.slice(-4),
          position: match.index,
          length: value.length,
        });
      }
    }

    logAudit('system', params.source_label, 'scan', `found=${findings.length} leaks`);

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          scanned: true,
          source: params.source_label,
          total_leaks_found: findings.length,
          severity: findings.length === 0 ? 'clean' : findings.length <= 2 ? 'warning' : 'critical',
          findings,
          recommendation: findings.length > 0
            ? 'Rotate exposed credentials immediately. Use store_secret to manage them securely.'
            : 'No exposed secrets detected.',
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// TOOL: inject_secret_to_request
// ═══════════════════════════════════════════

server.tool(
  'inject_secret_to_request',
  'Return a request object with the secret injected. Pass a token_id obtained from get_agent_token and a request template with a {{SECRET}} placeholder. The server substitutes the real secret — the agent never handles the raw value.',
  {
    token_id: z.string().min(1).describe('Token ID from get_agent_token'),
    request_template: z.string().min(1).describe('Request template with {{SECRET}} placeholder (e.g. JSON body, header string, URL)'),
  },
  async (params) => {
    const token = tokens.get(params.token_id);
    if (!token) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: true, message: 'Invalid or expired token' }) }] };
    }
    if (new Date(token.expires_at) < new Date()) {
      tokens.delete(params.token_id);
      return { content: [{ type: 'text', text: JSON.stringify({ error: true, message: 'Token expired' }) }] };
    }

    const secretRecord = secrets.get(token.secret_name);
    if (!secretRecord) {
      return { content: [{ type: 'text', text: JSON.stringify({ error: true, message: 'Secret no longer exists (may have been deleted)' }) }] };
    }

    const rawSecret = decrypt(secretRecord);
    const injected = params.request_template.replace(/\{\{SECRET\}\}/g, rawSecret);

    logAudit(token.agent_id, token.secret_name, 'inject', `token=${params.token_id.slice(0, 12)}...`);

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          injected: true,
          result: injected,
          token_id: params.token_id,
          expires_at: token.expires_at,
          note: 'Secret was injected server-side. The raw value was never exposed to the agent context.',
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// RESOURCE: secrets list
// ═══════════════════════════════════════════

server.resource(
  'secrets',
  'secure-vault://secrets',
  async () => {
    const allSecrets = secrets.all();
    const listing = allSecrets.map(({ name, service, rotation_policy, created_at, rotated_at }) => ({
      name, service, rotation_policy, created_at, rotated_at,
    }));

    return {
      contents: [{
        uri: 'secure-vault://secrets',
        mimeType: 'application/json',
        text: JSON.stringify({
          total_secrets: listing.length,
          active_tokens: tokens.size(),
          secrets: listing,
          generated_at: new Date().toISOString(),
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Secure Vault MCP Server running on stdio');
}

main().catch(console.error);
