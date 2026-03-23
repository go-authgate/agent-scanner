# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

Agent Scanner is a security scanner for AI agents, MCP servers, and agent skills. It discovers installed AI agent clients (Claude Desktop, Cursor, VS Code, Windsurf, etc.), connects to their configured MCP servers, and detects prompt injections, tool poisoning, toxic flows, and other security threats.

## Development Commands

### Building and Running

```bash
make build          # Build binary → bin/agent-scanner
go run ./cmd/agent-scanner  # Run directly
make rebuild        # Clean and rebuild
```

### Testing

```bash
make test           # Run all tests with race detector + coverage
make coverage       # Open coverage report in browser
go test -v -run TestFunctionName ./internal/...  # Run a single test
```

### Code Quality

```bash
make lint           # Run golangci-lint
make fmt            # Format code
make vet            # Run go vet
```

### Cross-Platform Builds

```bash
make build_linux_amd64    # Linux x86-64
make build_linux_arm64    # Linux ARM64
make build_darwin_amd64   # macOS x86-64
make build_darwin_arm64   # macOS ARM64
make build_windows_amd64  # Windows x86-64
```

## Architecture

### Pipeline: Discovery → Inspect → Analyze → Report/Push

1. **Discovery** (`internal/discovery/`): Platform-specific client detection + MCP config parsing
2. **Inspect** (`internal/inspect/`): Connect to MCP servers, extract tool/prompt/resource signatures
3. **Analyze** (`internal/rules/` + `internal/analysis/`): Local rule engine + optional remote API
4. **Report** (`internal/output/`): Colored terminal or JSON output
5. **Push** (`internal/upload/`): Upload redacted results to control servers

### Package Structure

- `internal/models/` — Zero-dependency domain types (ServerConfig, Entity, Issue, etc.)
- `internal/discovery/` — Client discovery + config parsing (build-tagged per platform)
- `internal/mcpclient/` — MCP protocol client (JSON-RPC 2.0 over stdio/SSE/HTTP)
- `internal/inspect/` — Server + skill inspection
- `internal/rules/` — Security rule engine (E001-E006, W001-W013, TF001-TF002)
- `internal/analysis/` — Remote analysis API client
- `internal/pipeline/` — 3-stage orchestrator
- `internal/output/` — Text + JSON formatters
- `internal/redact/` — Sensitive data redaction
- `internal/upload/` — Control server upload
- `internal/signed/` — macOS code signature verification
- `internal/mcpserver/` — Self-as-MCP-server mode
- `internal/cli/` — Cobra CLI commands
- `internal/version/` — Build-time version info

## Coding Conventions

- **IMPORTANT**: Before committing changes:
  1. **Write tests**: All new features and bug fixes MUST include corresponding unit tests
  2. **Format code**: Run `make fmt` to automatically fix formatting issues
  3. **Pass linting**: Run `make lint` to verify code passes linting without errors
- Use `log/slog` for structured logging
- Use `context.Context` for timeout/cancellation propagation
- Use `golang.org/x/sync/errgroup` for bounded concurrent work
- Platform-specific code uses Go build tags (`clients_darwin.go`, etc.)
- Interfaces defined where consumers need them, not where implementations live
