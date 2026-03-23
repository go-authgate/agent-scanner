package models

import "testing"

func TestServerConfigJSONToStdioServer(t *testing.T) {
	raw := ServerConfigJSON{
		Command: "npx",
		Args:    []string{"-y", "some-package"},
		Env:     map[string]string{"FOO": "bar"},
	}

	cfg := raw.ToServerConfig()
	stdio, ok := cfg.(*StdioServer)
	if !ok {
		t.Fatalf("expected *StdioServer, got %T", cfg)
	}
	if stdio.Command != "npx" {
		t.Errorf("expected command=npx, got %s", stdio.Command)
	}
	if len(stdio.Args) != 2 {
		t.Errorf("expected 2 args, got %d", len(stdio.Args))
	}
	if stdio.GetServerType() != ServerTypeStdio {
		t.Errorf("expected type=stdio, got %s", stdio.GetServerType())
	}
}

func TestServerConfigJSONToRemoteServer(t *testing.T) {
	raw := ServerConfigJSON{
		URL:  "https://example.com/mcp",
		Type: "sse",
	}

	cfg := raw.ToServerConfig()
	remote, ok := cfg.(*RemoteServer)
	if !ok {
		t.Fatalf("expected *RemoteServer, got %T", cfg)
	}
	if remote.URL != "https://example.com/mcp" {
		t.Errorf("expected URL, got %s", remote.URL)
	}
	if remote.GetServerType() != ServerTypeSSE {
		t.Errorf("expected type=sse, got %s", remote.GetServerType())
	}
}

func TestClaudeConfigFileGetServers(t *testing.T) {
	cfg := ClaudeConfigFile{
		MCPServers: map[string]ServerConfigJSON{
			"test": {Command: "test-server"},
		},
	}

	servers := cfg.GetServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if _, ok := servers["test"]; !ok {
		t.Error("expected 'test' server in map")
	}
	if cfg.ConfigType() != "claude" {
		t.Errorf("expected config type 'claude', got %s", cfg.ConfigType())
	}
}

func TestVSCodeMCPConfigFileGetServers(t *testing.T) {
	cfg := VSCodeMCPConfigFile{
		Servers: map[string]ServerConfigJSON{
			"s1": {URL: "https://example.com"},
			"s2": {Command: "my-server"},
		},
	}

	servers := cfg.GetServers()
	if len(servers) != 2 {
		t.Errorf("expected 2 servers, got %d", len(servers))
	}
}

func TestUnknownMCPConfig(t *testing.T) {
	cfg := UnknownMCPConfig{}
	if cfg.ConfigType() != "unknown" {
		t.Error("expected config type 'unknown'")
	}
	if servers := cfg.GetServers(); servers != nil {
		t.Error("expected nil servers")
	}
}
