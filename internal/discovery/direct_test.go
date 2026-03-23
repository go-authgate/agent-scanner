package discovery

import (
	"testing"

	"github.com/go-authgate/agent-scanner/internal/models"
)

func TestIsDirectScan(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"streamable-https://example.com/mcp", true},
		{"streamable-http://localhost:3000", true},
		{"sse://example.com/events", true},
		{"npm:@modelcontextprotocol/server@1.0.0", true},
		{"pypi:some-mcp-server@0.1.0", true},
		{"oci://docker.io/myimage:latest", true},
		{"/path/to/config.json", false},
		{"https://example.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := IsDirectScan(tt.path); got != tt.expected {
				t.Errorf("IsDirectScan(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestDirectScanToServerConfig(t *testing.T) {
	t.Run("streamable-https", func(t *testing.T) {
		name, cfg := DirectScanToServerConfig("streamable-https://example.com/mcp")
		if name != "https://example.com/mcp" {
			t.Errorf("expected name=https://example.com/mcp, got %s", name)
		}
		remote, ok := cfg.(*models.RemoteServer)
		if !ok {
			t.Fatalf("expected *RemoteServer, got %T", cfg)
		}
		if remote.URL != "https://example.com/mcp" {
			t.Errorf("expected URL=https://example.com/mcp, got %s", remote.URL)
		}
		if remote.Type != models.ServerTypeHTTP {
			t.Errorf("expected type=http, got %s", remote.Type)
		}
	})

	t.Run("sse", func(t *testing.T) {
		_, cfg := DirectScanToServerConfig("sse://example.com/events")
		remote, ok := cfg.(*models.RemoteServer)
		if !ok {
			t.Fatalf("expected *RemoteServer, got %T", cfg)
		}
		if remote.Type != models.ServerTypeSSE {
			t.Errorf("expected type=sse, got %s", remote.Type)
		}
	})

	t.Run("npm", func(t *testing.T) {
		name, cfg := DirectScanToServerConfig("npm:@modelcontextprotocol/server@1.0.0")
		if name != "@modelcontextprotocol/server" {
			t.Errorf("expected name=@modelcontextprotocol/server, got %s", name)
		}
		stdio, ok := cfg.(*models.StdioServer)
		if !ok {
			t.Fatalf("expected *StdioServer, got %T", cfg)
		}
		if stdio.Command != "npx" {
			t.Errorf("expected command=npx, got %s", stdio.Command)
		}
	})

	t.Run("pypi", func(t *testing.T) {
		name, cfg := DirectScanToServerConfig("pypi:some-server@0.1.0")
		if name != "some-server" {
			t.Errorf("expected name=some-server, got %s", name)
		}
		stdio, ok := cfg.(*models.StdioServer)
		if !ok {
			t.Fatalf("expected *StdioServer, got %T", cfg)
		}
		if stdio.Command != "uvx" {
			t.Errorf("expected command=uvx, got %s", stdio.Command)
		}
	})

	t.Run("oci", func(t *testing.T) {
		_, cfg := DirectScanToServerConfig("oci://myimage:latest")
		stdio, ok := cfg.(*models.StdioServer)
		if !ok {
			t.Fatalf("expected *StdioServer, got %T", cfg)
		}
		if stdio.Command != "docker" {
			t.Errorf("expected command=docker, got %s", stdio.Command)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		_, cfg := DirectScanToServerConfig("unknown://something")
		if cfg != nil {
			t.Error("expected nil for unknown scheme")
		}
	})
}

func TestParsePackageNameVersion(t *testing.T) {
	tests := []struct {
		pkg         string
		wantName    string
		wantVersion string
	}{
		{"package", "package", ""},
		{"package@1.0.0", "package", "1.0.0"},
		{"@scope/package@2.0.0", "@scope/package", "2.0.0"},
		{"@scope/package", "@scope/package", ""},
	}

	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			name, version := parsePackageNameVersion(tt.pkg)
			if name != tt.wantName {
				t.Errorf("parsePackageNameVersion(%q) name = %q, want %q", tt.pkg, name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("parsePackageNameVersion(%q) version = %q, want %q", tt.pkg, version, tt.wantVersion)
			}
		})
	}
}
