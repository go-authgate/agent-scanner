package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseMCPConfigFile_Claude(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude_desktop_config.json")
	content := `{
		"mcpServers": {
			"test-server": {
				"command": "npx",
				"args": ["-y", "test-package"]
			}
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := ParseMCPConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ConfigType() != "claude" {
		t.Errorf("expected config type 'claude', got %s", cfg.ConfigType())
	}

	servers := cfg.GetServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
}

func TestParseMCPConfigFile_VSCode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	content := `{
		"mcp": {
			"servers": {
				"remote-server": {
					"url": "https://example.com/mcp",
					"type": "sse"
				}
			}
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := ParseMCPConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ConfigType() != "vscode" {
		t.Errorf("expected config type 'vscode', got %s", cfg.ConfigType())
	}

	servers := cfg.GetServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
}

func TestParseMCPConfigFile_VSCodeMCP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	content := `{
		"servers": {
			"my-server": {
				"command": "my-mcp-server",
				"args": ["--port", "3000"]
			}
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := ParseMCPConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ConfigType() != "vscode_mcp" {
		t.Errorf("expected config type 'vscode_mcp', got %s", cfg.ConfigType())
	}
}

func TestParseMCPConfigFile_JSONC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	// JSONC with comments
	content := `{
		// This is a comment
		"mcp": {
			"servers": {
				"test": {
					"command": "test-cmd"
					/* block comment */
				}
			}
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := ParseMCPConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}

	servers := cfg.GetServers()
	if len(servers) != 1 {
		t.Errorf("expected 1 server from JSONC, got %d", len(servers))
	}
}

func TestParseMCPConfigFile_Unknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"some_random_key": "value"}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := ParseMCPConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ConfigType() != "unknown" {
		t.Errorf("expected config type 'unknown', got %s", cfg.ConfigType())
	}
}

func TestParseMCPConfigFile_NotFound(t *testing.T) {
	_, err := ParseMCPConfigFile("/nonexistent/path.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
