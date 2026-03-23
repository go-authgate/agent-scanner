# Agent Scanner

Security scanner for AI agents, MCP servers, and agent skills. Discovers installed AI agent clients, connects to their configured MCP servers, and detects prompt injections, tool poisoning, toxic flows, and other security threats.

Inspired by [snyk/agent-scan](https://github.com/snyk/agent-scan), reimplemented in Go as a single static binary.

## Features

- **Auto-discovery** of 11+ AI agent clients (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, Kiro, Codex, etc.)
- **MCP protocol client** supporting stdio, SSE, and streamable HTTP transports
- **13 security rules** detecting prompt injections, tool shadowing, hardcoded secrets, malicious code, toxic flows, and more
- **Skill scanning** for agent skill directories containing `SKILL.md`
- **Direct scanning** from package managers (`npm:`, `pypi:`, `oci://`) and URLs (`sse://`, `streamable-http://`)
- **Cross-platform** support (macOS, Linux, Windows)
- **Single binary** with zero runtime dependencies

## Installation

### From source

```bash
git clone https://github.com/go-authgate/agent-scanner.git
cd agent-scanner
make build
```

Binary will be at `bin/agent-scanner`.

### Cross-platform builds

```bash
make build_linux_amd64
make build_linux_arm64
make build_darwin_amd64
make build_darwin_arm64
make build_windows_amd64
```

## Usage

### Scan (default)

Discover and scan all MCP servers on your machine:

```bash
agent-scanner scan
```

Scan a specific config file:

```bash
agent-scanner scan ~/.cursor/mcp.json
```

Scan a remote MCP server directly:

```bash
agent-scanner scan sse://localhost:3000/sse
agent-scanner scan streamable-https://example.com/mcp
```

Scan an npm/PyPI MCP package:

```bash
agent-scanner scan npm:@modelcontextprotocol/server-filesystem@latest
agent-scanner scan pypi:mcp-server-sqlite@0.1.0
```

### Scan Skills

Scan a single skill directory (must contain `SKILL.md`):

```bash
agent-scanner scan ./path/to/my-skill
```

Scan a parent directory containing multiple skills:

```bash
agent-scanner scan ./skills/
```

Auto-discover and scan skills from known client directories (e.g. `~/.claude/commands`):

```bash
agent-scanner scan --skills
```

### Inspect

List tools, prompts, and resources without security analysis:

```bash
agent-scanner inspect
```

### Options

```text
--json                     Output results as JSON
--skills                   Include skill directory scanning
--verbose                  Enable verbose logging
--server-timeout N         MCP server connection timeout in seconds (default: 10)
--skip-ssl-verify          Disable SSL certificate verification
--scan-all-users           Scan all user home directories
--print-errors             Show server startup errors/tracebacks
--print-full-descriptions  Show full entity descriptions
--analysis-url URL         Remote verification server URL
--control-server URL       Upload results to control server
```

### JSON output

```bash
agent-scanner scan --json | jq '.[] | .issues'
```

## Issue Codes

### Critical (E-codes)

| Code | Description                                  |
| ---- | -------------------------------------------- |
| E001 | Prompt injection in tool description         |
| E002 | Cross-server tool reference (tool shadowing) |
| E003 | Tool description hijacks agent behavior      |
| E004 | Prompt injection in skill                    |
| E005 | Suspicious download URL in skill             |
| E006 | Malicious code patterns in skill             |

### Warnings (W-codes)

| Code | Description                              |
| ---- | ---------------------------------------- |
| W001 | Suspicious trigger words in descriptions |
| W002 | Too many entities (>100)                 |
| W007 | Insecure credential handling             |
| W008 | Hardcoded secrets                        |
| W009 | Direct financial execution capability    |
| W011 | Untrusted third-party content exposure   |
| W012 | Unverifiable external dependencies       |
| W013 | System service modification              |

### Toxic Flows (TF-codes)

| Code  | Description                                                    |
| ----- | -------------------------------------------------------------- |
| TF001 | Data leak flow (untrusted source → private data → public sink) |
| TF002 | Destructive flow (untrusted source → irreversible action)      |

## Supported Clients

| Client         | macOS | Linux | Windows |
| -------------- | ----- | ----- | ------- |
| Claude Desktop | ✓     | —     | ✓       |
| Claude Code    | ✓     | ✓     | ✓       |
| Cursor         | ✓     | ✓     | ✓       |
| VS Code        | ✓     | ✓     | ✓       |
| Windsurf       | ✓     | ✓     | ✓       |
| Gemini CLI     | ✓     | ✓     | ✓       |
| Kiro           | ✓     | ✓     | ✓       |
| Codex          | ✓     | ✓     | ✓       |
| OpenCode       | ✓     | ✓     | —       |
| OpenClaw       | ✓     | ✓     | ✓       |
| Antigravity    | ✓     | ✓     | —       |

## Architecture

```text
Discovery → Inspect → Analyze → Report/Push
```

1. **Discovery** — Find installed AI agent clients and parse their MCP config files
2. **Inspect** — Connect to MCP servers concurrently, extract tool/prompt/resource signatures
3. **Analyze** — Run local security rules + optional remote ML-based analysis
4. **Report** — Output as colored terminal text or JSON
5. **Push** — Upload redacted results to control servers

## Development

```bash
make test       # Run tests with coverage
make lint       # Run golangci-lint
make fmt        # Format code
make build      # Build binary
```

## License

See [LICENSE](LICENSE) for details.
