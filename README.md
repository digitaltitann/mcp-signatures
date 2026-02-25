# MCP Signatures

Community threat signatures for [MCP Scanner](https://github.com/digitaltitann/mcp-scanner). Provides regularly updated detection patterns for malicious Claude Code plugins, skills, hooks, and MCP servers.

## Quick Start

```bash
# Configure the feed (one-time setup)
python ~/.claude/plugins/mcp-scanner/scripts/update_signatures.py --set-feed https://raw.githubusercontent.com/digitaltitann/mcp-signatures/main/signatures.json

# Fetch latest signatures
python ~/.claude/plugins/mcp-scanner/scripts/update_signatures.py --fetch

# Verify
python ~/.claude/plugins/mcp-scanner/scripts/update_signatures.py --show
```

On Windows:
```powershell
python $env:USERPROFILE\.claude\plugins\mcp-scanner\scripts\update_signatures.py --set-feed https://raw.githubusercontent.com/digitaltitann/mcp-signatures/main/signatures.json
python $env:USERPROFILE\.claude\plugins\mcp-scanner\scripts\update_signatures.py --fetch
```

## What's Included

This feed extends MCP Scanner's 75 built-in signatures with additional patterns across these categories:

| Category | Patterns | Description |
|----------|----------|-------------|
| Prompt Injection | 10 | DAN jailbreaks, system prompt extraction, developer mode, XML tag injection, hidden comments, multi-turn manipulation, warning suppression, token exhaustion |
| Data Exfiltration | 6 | DNS exfil, clipboard access, WebSocket channels, screenshots, URL parameter encoding, error reporting abuse |
| Credential Theft | 10 | AWS/GCP/Azure credentials, NPM tokens, GitHub PATs, Docker auth, Kubernetes configs, macOS Keychain, Windows Credential Manager, browser passwords |
| Code Execution | 6 | Function constructor, dynamic imports, vm module, WASM, Python compile+exec, importlib |
| Network Abuse | 3 | Tunneling services (ngrok), Tor/.onion, C2 via chat webhooks |
| File System Abuse | 4 | Git hooks, IDE settings, Claude settings, package manager configs |
| Obfuscation | 3 | JS obfuscation tools, Python obfuscators, rot13/substitution ciphers |
| Hook Hijacking | 3 | Input modification, session capture, auto-approval bypass |
| Rug Pull | 3 | Time-based triggers, remote kill switches, counter-based activation |
| Supply Chain | 3 | Postinstall network requests, download-and-execute, git submodules |
| MCP-Specific | 4 | Tool description injection, tool name shadowing, response manipulation, cross-tool data leakage |
| Known Malicious | 5 | Credential harvesters, env dumpers, SSH key exfil, browser stealers, persistence installers |

**Total: 56 line patterns + 4 multiline patterns + 5 known malicious signatures**

## How Merging Works

When you run `--fetch`, remote signatures are merged with your local `signatures.json`:

- Remote patterns **override** local patterns with the same ID
- Local-only patterns (IDs not in remote) are **preserved**
- All patterns are validated before merge (regex compilation, required fields, severity values)
- A backup is created before any changes

## Signature Format

### Line Pattern

```json
{
  "id": "EXT_CRED_001",
  "category": "credential-theft",
  "severity": "CRITICAL",
  "description": "AWS credentials file access",
  "regex": "(?:\\.aws[/\\\\](?:credentials|config)|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)",
  "flags": "IGNORECASE",
  "file_types": [".py", ".js", ".ts", ".sh"],
  "context_note": "Accessing AWS credential files for cloud account compromise"
}
```

### Multiline Pattern

```json
{
  "id": "EXT_ML_002",
  "category": "credential-theft",
  "severity": "CRITICAL",
  "description": "Environment variable collection followed by network send",
  "regex": "(?:os\\.environ|process\\.env).*(?:requests|fetch|urllib)",
  "flags": "DOTALL",
  "file_types": [".py", ".js", ".ts"],
  "context_note": "Collecting env vars and sending them to a server"
}
```

### Known Malicious Signature

```json
{
  "id": "EXT_MAL_002",
  "name": "mcp-env-dumper",
  "description": "Dumps all environment variables and sends them externally",
  "severity": "CRITICAL",
  "fingerprints": [
    "os\\.environ\\.items|Object\\.entries\\(process\\.env\\)",
    "json\\.dumps|JSON\\.stringify",
    "requests\\.post|fetch|urllib"
  ],
  "fingerprint_flags": ["", "", ""],
  "min_matches": 3,
  "file_types": [".py", ".js", ".ts"]
}
```

### Field Reference

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier. Convention: `EXT_CATEGORY_NNN` |
| `category` | Yes | One of: `prompt-injection`, `data-exfiltration`, `code-execution`, `credential-theft`, `network-abuse`, `obfuscation`, `filesystem-abuse`, `over-broad-permissions`, `hook-hijacking`, `rug-pull`, `supply-chain`, `mcp-specific`, `known-malicious` |
| `severity` | Yes | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `description` | Yes | Human-readable description of what the pattern detects |
| `regex` | Yes (patterns) | Python-compatible regular expression |
| `flags` | No | Regex flags: `IGNORECASE`, `DOTALL`, `MULTILINE` (comma-separated) |
| `file_types` | Yes | List of file extensions to check (e.g., `[".py", ".js"]`) |
| `context_note` | No | Additional context about why this pattern is a threat |
| `fingerprints` | Yes (known_malicious) | List of regex patterns that must match together |
| `fingerprint_flags` | No | Per-fingerprint regex flags |
| `min_matches` | Yes (known_malicious) | Minimum fingerprint matches to trigger |

## Contributing

1. Fork this repository
2. Add your signature to `signatures.json`
3. Validate: `python ~/.claude/plugins/mcp-scanner/scripts/update_signatures.py --validate`
4. Submit a pull request with:
   - What the pattern detects
   - Example of code it would catch
   - Why existing patterns don't cover it

### Guidelines

- Use `EXT_` prefix for all IDs
- Test regex patterns against both malicious and benign code to minimize false positives
- Include `context_note` to help the scanner's semantic analysis phase
- For known malicious signatures, require at least 3 fingerprint matches to reduce false positives
- Avoid overlapping with MCP Scanner's 75 built-in patterns

## License

MIT
