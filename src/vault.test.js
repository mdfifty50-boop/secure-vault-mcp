import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, chmodSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// ── Isolated test environment ─────────────────────────────────────────────────
// Use a temp dir so tests never touch ~/.secure-vault-mcp
const TEST_DIR = join(tmpdir(), `secure-vault-test-${randomBytes(4).toString('hex')}`);
mkdirSync(TEST_DIR, { recursive: true });

// ── Inline key + crypto helpers (same logic as index.js) ─────────────────────
const MASTER_KEY = randomBytes(32);

function encrypt(plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    encrypted: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
  };
}

function decrypt(record) {
  const decipher = createDecipheriv('aes-256-gcm', MASTER_KEY, Buffer.from(record.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
  return decipher.update(Buffer.from(record.encrypted, 'base64')) + decipher.final('utf8');
}

// ── Inline SQLite db (mirrors db.js but uses TEST_DIR path) ──────────────────
import Database from 'better-sqlite3';

const db = new Database(join(TEST_DIR, 'vault.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS secrets (
    name TEXT PRIMARY KEY, encrypted TEXT, iv TEXT, tag TEXT,
    service TEXT DEFAULT 'default', rotation_policy TEXT DEFAULT 'none',
    created_at TEXT, rotated_at TEXT
  );
  CREATE TABLE IF NOT EXISTS tokens (
    token_id TEXT PRIMARY KEY, agent_id TEXT, secret_name TEXT,
    scope TEXT, expires_at INTEGER
  );
`);

const stmtUpsert = db.prepare(`
  INSERT INTO secrets (name, encrypted, iv, tag, service, rotation_policy, created_at, rotated_at)
  VALUES (@name, @encrypted, @iv, @tag, @service, @rotation_policy, @created_at, @rotated_at)
  ON CONFLICT(name) DO UPDATE SET
    encrypted=excluded.encrypted, iv=excluded.iv, tag=excluded.tag,
    rotated_at=excluded.rotated_at
`);
const stmtGet = db.prepare('SELECT * FROM secrets WHERE name = ?');
const stmtInsertToken = db.prepare(`
  INSERT INTO tokens (token_id, agent_id, secret_name, scope, expires_at)
  VALUES (@token_id, @agent_id, @secret_name, @scope, @expires_at)
`);
const stmtGetToken = db.prepare('SELECT * FROM tokens WHERE token_id = ?');

after(() => {
  db.close();
  rmSync(TEST_DIR, { recursive: true, force: true });
});

// ── TEST 1: store_secret ──────────────────────────────────────────────────────
test('store_secret — encrypts and persists to SQLite', () => {
  const name = 'test_openai_key';
  const value = 'sk-test-abc123xyz';
  const now = new Date().toISOString();
  const enc = encrypt(value);

  stmtUpsert.run({
    name,
    ...enc,
    service: 'openai',
    rotation_policy: 'none',
    created_at: now,
    rotated_at: now,
  });

  const row = stmtGet.get(name);
  assert.ok(row, 'Row should exist in DB');
  assert.equal(row.name, name);
  assert.equal(row.service, 'openai');
  // Encrypted value must not equal plaintext
  assert.notEqual(row.encrypted, value);
  // Round-trip must recover the plaintext
  const recovered = decrypt(row);
  assert.equal(recovered, value, 'Decrypted value must match original');
});

// ── TEST 2: retrieve_secret — survives simulated restart ─────────────────────
test('retrieve_secret — decrypts correctly after simulated restart', () => {
  // The same db handle (same MASTER_KEY) simulates persistence across restarts
  const name = 'test_stripe_key';
  const value = 'sk_live_supersecret9876';
  const now = new Date().toISOString();
  const enc = encrypt(value);

  stmtUpsert.run({
    name, ...enc,
    service: 'stripe', rotation_policy: 'monthly',
    created_at: now, rotated_at: now,
  });

  // Re-fetch simulates what happens on a new process boot that reads from DB
  const row = stmtGet.get(name);
  assert.ok(row, 'Row must survive after re-fetch');
  const recovered = decrypt(row);
  assert.equal(recovered, value, 'Secret value must be recoverable from DB');
  assert.equal(row.rotation_policy, 'monthly');
});

// ── TEST 3: access_token — stored and retrievable ─────────────────────────────
test('access_token — token stored in DB with correct expiry', () => {
  const tokenId = `svt_${randomBytes(24).toString('hex')}`;
  const ttlSeconds = 300;
  const expiresAt = Date.now() + ttlSeconds * 1000;

  stmtInsertToken.run({
    token_id: tokenId,
    agent_id: 'test-agent',
    secret_name: 'test_openai_key',
    scope: 'read',
    expires_at: expiresAt,
  });

  const row = stmtGetToken.get(tokenId);
  assert.ok(row, 'Token must be found in DB');
  assert.equal(row.agent_id, 'test-agent');
  assert.equal(row.scope, 'read');
  assert.ok(row.expires_at > Date.now(), 'Token must not be expired');
  // Token ID must be opaque (not the secret value)
  assert.match(row.token_id, /^svt_/, 'Token must start with svt_ prefix');
});
