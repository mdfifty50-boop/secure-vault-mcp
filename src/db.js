import Database from 'better-sqlite3';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { mkdirSync } from 'node:fs';

const VAULT_DIR = join(homedir(), '.secure-vault-mcp');
mkdirSync(VAULT_DIR, { recursive: true });

const DB_PATH = join(VAULT_DIR, 'vault.db');

const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS secrets (
    name            TEXT PRIMARY KEY,
    encrypted       TEXT NOT NULL,
    iv              TEXT NOT NULL,
    tag             TEXT NOT NULL,
    service         TEXT NOT NULL DEFAULT 'default',
    rotation_policy TEXT NOT NULL DEFAULT 'none',
    created_at      TEXT NOT NULL,
    rotated_at      TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS tokens (
    token_id    TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    secret_name TEXT NOT NULL,
    scope       TEXT NOT NULL,
    expires_at  INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    secret_name TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT ''
  );
`);

// ── Secrets ──────────────────────────────────────────────────────────────────

const stmtUpsertSecret = db.prepare(`
  INSERT INTO secrets (name, encrypted, iv, tag, service, rotation_policy, created_at, rotated_at)
  VALUES (@name, @encrypted, @iv, @tag, @service, @rotation_policy, @created_at, @rotated_at)
  ON CONFLICT(name) DO UPDATE SET
    encrypted       = excluded.encrypted,
    iv              = excluded.iv,
    tag             = excluded.tag,
    service         = excluded.service,
    rotation_policy = excluded.rotation_policy,
    rotated_at      = excluded.rotated_at
`);

const stmtGetSecret = db.prepare('SELECT * FROM secrets WHERE name = ?');
const stmtGetSecretByService = db.prepare('SELECT * FROM secrets WHERE service = ?');
const stmtGetAllSecrets = db.prepare('SELECT * FROM secrets');
const stmtDeleteSecret = db.prepare('DELETE FROM secrets WHERE name = ?');

export const secrets = {
  set: (name, record) => stmtUpsertSecret.run({ name, ...record }),
  get: (name) => stmtGetSecret.get(name) ?? null,
  getByService: (service) => stmtGetSecretByService.all(service),
  all: () => stmtGetAllSecrets.all(),
  delete: (name) => stmtDeleteSecret.run(name),
  // Mimic Map iteration for compatibility
  [Symbol.iterator]: function* () {
    for (const row of stmtGetAllSecrets.all()) yield [row.name, row];
  },
};

// ── Tokens ───────────────────────────────────────────────────────────────────

const stmtInsertToken = db.prepare(`
  INSERT OR REPLACE INTO tokens (token_id, agent_id, secret_name, scope, expires_at)
  VALUES (@token_id, @agent_id, @secret_name, @scope, @expires_at)
`);

const stmtGetToken = db.prepare('SELECT * FROM tokens WHERE token_id = ?');
const stmtDeleteToken = db.prepare('DELETE FROM tokens WHERE token_id = ?');
const stmtDeleteTokensBySecret = db.prepare('DELETE FROM tokens WHERE secret_name = ?');
const stmtCountTokens = db.prepare('SELECT COUNT(*) AS cnt FROM tokens');
const stmtGetTokensBySecret = db.prepare('SELECT token_id FROM tokens WHERE secret_name = ?');

export const tokens = {
  set: (token_id, { agent_id, secret_name, scope, expires_at }) => {
    // Store expires_at as epoch ms integer for easy comparison
    const expires_ms = new Date(expires_at).getTime();
    stmtInsertToken.run({ token_id, agent_id, secret_name, scope, expires_at: expires_ms });
  },
  get: (token_id) => {
    const row = stmtGetToken.get(token_id);
    if (!row) return null;
    // Rehydrate expires_at as ISO string to match original interface
    return { ...row, expires_at: new Date(row.expires_at).toISOString() };
  },
  delete: (token_id) => stmtDeleteToken.run(token_id),
  deleteBySecret: (secret_name) => stmtDeleteTokensBySecret.run(secret_name),
  size: () => stmtCountTokens.get().cnt,
  tokensBySecret: (secret_name) => stmtGetTokensBySecret.all(secret_name).map((r) => r.token_id),
};

// ── Audit Log ─────────────────────────────────────────────────────────────────

const stmtInsertAudit = db.prepare(`
  INSERT INTO audit_log (timestamp, agent_id, secret_name, action, detail)
  VALUES (@timestamp, @agent_id, @secret_name, @action, @detail)
`);

const stmtQueryAudit = db.prepare(`
  SELECT timestamp, agent_id, secret_name, action, detail
  FROM audit_log
  WHERE timestamp >= @cutoff
  ORDER BY id DESC
  LIMIT 100
`);

const stmtQueryAuditFiltered = db.prepare(`
  SELECT timestamp, agent_id, secret_name, action, detail
  FROM audit_log
  WHERE timestamp >= @cutoff
    AND (@agent_id  IS NULL OR agent_id    = @agent_id)
    AND (@secret_name IS NULL OR secret_name = @secret_name)
  ORDER BY id DESC
  LIMIT 100
`);

const stmtCountAudit = db.prepare(`
  SELECT COUNT(*) AS cnt FROM audit_log
  WHERE timestamp >= @cutoff
    AND (@agent_id    IS NULL OR agent_id    = @agent_id)
    AND (@secret_name IS NULL OR secret_name = @secret_name)
`);

export const auditLog = {
  push: ({ timestamp, agent_id, secret_name, action, detail = '' }) =>
    stmtInsertAudit.run({ timestamp, agent_id, secret_name, action, detail }),

  query: ({ cutoff, agent_id = null, secret_name = null }) => {
    const cutoffIso = new Date(cutoff).toISOString();
    const total = stmtCountAudit.get({ cutoff: cutoffIso, agent_id, secret_name }).cnt;
    const entries = stmtQueryAuditFiltered.all({ cutoff: cutoffIso, agent_id, secret_name });
    return { total, entries };
  },
};

export default db;
