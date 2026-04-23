# secure-vault-mcp

MCP server for agent-native secrets management. 24,008 secrets have been found in MCP config files on public GitHub. This server solves that.

Agents need secrets to call APIs, but they shouldn't see raw values. secure-vault-mcp stores secrets encrypted with AES-256-GCM, issues short-lived scoped tokens, and injects secrets into requests server-side so the agent never handles plaintext credentials.

## Install

```bash
npx secure-vault-mcp
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "secure-vault": {
      "command": "npx",
      "args": ["secure-vault-mcp"]
    }
  }
}
```

### From source

```bash
git clone https://github.com/mdfifty50-boop/secure-vault-mcp.git
cd secure-vault-mcp
npm install
node src/index.js
```

## Tools

### store_secret

Store an encrypted secret with optional rotation policy.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Secret name (e.g. "openai_api_key") |
| `value` | string | required | Secret value — encrypted immediately |
| `service` | string | `"default"` | Service this secret belongs to |
| `rotation_policy` | string | `"none"` | `"none"`, `"daily"`, `"weekly"`, `"monthly"` |

### get_agent_token

Issue a short-lived, scoped token. The agent receives an opaque token ID, never the raw secret.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `agent_id` | string | required | Requesting agent identifier |
| `service` | string | required | Service to get a token for |
| `scope` | string | `"read"` | `"read"`, `"write"`, `"admin"` |
| `ttl_seconds` | number | 300 | Token TTL (10s to 86400s) |

### rotate_secrets

Rotate all secrets for a service. Old tokens are invalidated.

| Param | Type | Description |
|-------|------|-------------|
| `service` | string | Service whose secrets to rotate |
| `new_value` | string | New secret value |

### audit_secret_access

View who accessed what secrets over a time range.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `time_range` | string | `"24h"` | `"1h"`, `"6h"`, `"24h"`, `"7d"`, `"all"` |
| `agent_id` | string | optional | Filter by agent |
| `secret_name` | string | optional | Filter by secret |

### scan_config_for_leaks

Scan config text for exposed secrets. Detects AWS keys, GitHub tokens, OpenAI/Anthropic keys, Slack tokens, Stripe keys, private key blocks, bearer tokens, and generic credentials using 12 regex patterns.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `config_text` | string | required | Config content to scan |
| `source_label` | string | `"unknown"` | Label for audit trail |

### inject_secret_to_request

Return a request with the secret injected server-side. The agent provides a template with `{{SECRET}}` placeholder and a valid token ID.

| Param | Type | Description |
|-------|------|-------------|
| `token_id` | string | Token from get_agent_token |
| `request_template` | string | Template with `{{SECRET}}` placeholder |

## Resources

| URI | Description |
|-----|-------------|
| `secure-vault://secrets` | All stored secret names with metadata (no raw values) |

## Usage Pattern

```
1. store_secret — store credentials at setup time
2. get_agent_token — agent requests a scoped, time-limited token
3. inject_secret_to_request — inject secret into API call template
4. rotate_secrets — rotate when needed, old tokens auto-invalidate
5. scan_config_for_leaks — check config files before committing
6. audit_secret_access — review access trail
```

## Security Model

- Secrets encrypted at rest with AES-256-GCM using a server-generated key
- Agents receive opaque token IDs, never raw secret values
- Tokens are scoped (read/write/admin) and time-limited (default 5 minutes)
- Token rotation invalidates all outstanding tokens for the rotated secret
- Full audit trail of every store, token issuance, and injection
- In-memory storage — secrets exist only for the server session lifetime

## Tests

```bash
npm test
```

## License

MIT
