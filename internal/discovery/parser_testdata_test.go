package discovery

import (
	"path/filepath"
	"runtime"
	"testing"
)

func testdataPath(parts ...string) string {
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	base := filepath.Join(dir, "..", "..", "testdata")
	return filepath.Join(append([]string{base}, parts...)...)
}

func TestParseMCPConfigFile_Testdata_Claude(t *testing.T) {
	path := testdataPath("configs", "claude_desktop_config.json")
	cfg, err := ParseMCPConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigType() != "claude" {
		t.Errorf("expected 'claude', got %s", cfg.ConfigType())
	}
	servers := cfg.GetServers()
	if len(servers) != 2 {
		t.Errorf("expected 2 servers, got %d", len(servers))
	}
}

func TestParseMCPConfigFile_Testdata_ClaudeCode(t *testing.T) {
	path := testdataPath("configs", "claude_code_config.json")
	cfg, err := ParseMCPConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigType() != "claude_code" {
		t.Errorf("expected 'claude_code', got %s", cfg.ConfigType())
	}
	servers := cfg.GetServers()
	if len(servers) != 2 {
		t.Errorf("expected 2 servers (global + project), got %d", len(servers))
	}
}

func TestParseMCPConfigFile_Testdata_VSCode(t *testing.T) {
	path := testdataPath("configs", "vscode_settings.json")
	cfg, err := ParseMCPConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigType() != "vscode" {
		t.Errorf("expected 'vscode', got %s", cfg.ConfigType())
	}
	servers := cfg.GetServers()
	if len(servers) != 2 {
		t.Errorf("expected 2 servers, got %d", len(servers))
	}
}

func TestParseMCPConfigFile_Testdata_Cursor(t *testing.T) {
	path := testdataPath("configs", "cursor_mcp.json")
	cfg, err := ParseMCPConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigType() != "vscode_mcp" {
		t.Errorf("expected 'vscode_mcp', got %s", cfg.ConfigType())
	}
	servers := cfg.GetServers()
	if len(servers) != 1 {
		t.Errorf("expected 1 server, got %d", len(servers))
	}
}

func TestParseMCPConfigFile_Testdata_Windsurf(t *testing.T) {
	path := testdataPath("configs", "windsurf_mcp_config.json")
	cfg, err := ParseMCPConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	servers := cfg.GetServers()
	if len(servers) != 1 {
		t.Errorf("expected 1 server, got %d", len(servers))
	}
}

func TestParseMCPConfigFile_Testdata_Empty(t *testing.T) {
	path := testdataPath("configs", "empty.json")
	cfg, err := ParseMCPConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigType() != "unknown" {
		t.Errorf("expected 'unknown', got %s", cfg.ConfigType())
	}
}

func TestParseMCPConfigFile_Testdata_Malformed(t *testing.T) {
	path := testdataPath("configs", "malformed.json")
	cfg, err := ParseMCPConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// malformed JSON after stripping comments should result in unknown config
	if cfg.ConfigType() != "unknown" {
		t.Errorf("expected 'unknown', got %s", cfg.ConfigType())
	}
}

func TestParseMCPConfigFile_Testdata_MultipleTransport(t *testing.T) {
	path := testdataPath("configs", "multiple_transport.json")
	cfg, err := ParseMCPConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigType() != "vscode" {
		t.Errorf("expected 'vscode', got %s", cfg.ConfigType())
	}
	servers := cfg.GetServers()
	if len(servers) != 2 {
		t.Errorf("expected 2 servers (http_server + sse_server), got %d", len(servers))
	}
	// Verify both are remote servers with correct types
	for name, sc := range servers {
		switch name {
		case "http_server":
			if sc.GetServerType() != "http" {
				t.Errorf("expected http_server type 'http', got %s", sc.GetServerType())
			}
		case "sse_server":
			if sc.GetServerType() != "sse" {
				t.Errorf("expected sse_server type 'sse', got %s", sc.GetServerType())
			}
		default:
			t.Errorf("unexpected server name: %s", name)
		}
	}
}

func TestParseMCPConfigFile_Testdata_VSCodeWithoutMCP(t *testing.T) {
	path := testdataPath("configs", "vscode_without_mcp.json")
	cfg, err := ParseMCPConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigType() != "unknown" {
		t.Errorf("expected 'unknown', got %s", cfg.ConfigType())
	}
}

func TestParseMCPConfigFile_Testdata_VSCodeWithEmptyMCP(t *testing.T) {
	path := testdataPath("configs", "vscode_with_empty_mcp.json")
	cfg, err := ParseMCPConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigType() != "unknown" {
		t.Errorf("expected 'unknown', got %s", cfg.ConfigType())
	}
}
