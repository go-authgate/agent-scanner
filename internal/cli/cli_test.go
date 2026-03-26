package cli

import (
	"testing"
)

func TestParseControlServers_Empty(t *testing.T) {
	// Save and restore original scanFlags.
	orig := scanFlags
	defer func() { scanFlags = orig }()

	scanFlags = ScanFlags{}

	servers := parseControlServers()
	if servers != nil {
		t.Errorf("expected nil, got %v", servers)
	}
}

func TestParseControlServers_OneServer_NoIdentifier(t *testing.T) {
	orig := scanFlags
	defer func() { scanFlags = orig }()

	scanFlags = ScanFlags{
		ControlServers: []string{"https://control.example.com"},
	}

	servers := parseControlServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].URL != "https://control.example.com" {
		t.Errorf("unexpected URL: %s", servers[0].URL)
	}
	if servers[0].Identifier != "" {
		t.Errorf("expected empty identifier, got %q", servers[0].Identifier)
	}
}

func TestParseControlServers_MatchingServersAndIdentifiers(t *testing.T) {
	orig := scanFlags
	defer func() { scanFlags = orig }()

	scanFlags = ScanFlags{
		ControlServers:    []string{"https://a.example.com", "https://b.example.com"},
		ControlIdentifier: []string{"id-a", "id-b"},
	}

	servers := parseControlServers()
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	if servers[0].URL != "https://a.example.com" {
		t.Errorf("server[0] URL = %q, want %q", servers[0].URL, "https://a.example.com")
	}
	if servers[0].Identifier != "id-a" {
		t.Errorf("server[0] Identifier = %q, want %q", servers[0].Identifier, "id-a")
	}
	if servers[1].URL != "https://b.example.com" {
		t.Errorf("server[1] URL = %q, want %q", servers[1].URL, "https://b.example.com")
	}
	if servers[1].Identifier != "id-b" {
		t.Errorf("server[1] Identifier = %q, want %q", servers[1].Identifier, "id-b")
	}
}

func TestParseControlServers_MoreServersThanIdentifiers(t *testing.T) {
	orig := scanFlags
	defer func() { scanFlags = orig }()

	scanFlags = ScanFlags{
		ControlServers: []string{
			"https://a.example.com",
			"https://b.example.com",
			"https://c.example.com",
		},
		ControlIdentifier: []string{"id-a"},
	}

	servers := parseControlServers()
	if len(servers) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(servers))
	}

	if servers[0].URL != "https://a.example.com" {
		t.Errorf("server[0] URL = %q, want %q", servers[0].URL, "https://a.example.com")
	}
	if servers[0].Identifier != "id-a" {
		t.Errorf("server[0] Identifier = %q, want %q", servers[0].Identifier, "id-a")
	}

	// servers[1] and servers[2] have index >= len(ControlIdentifier), so identifier should be empty.
	if servers[1].Identifier != "" {
		t.Errorf("server[1] Identifier = %q, want empty", servers[1].Identifier)
	}
	if servers[2].Identifier != "" {
		t.Errorf("server[2] Identifier = %q, want empty", servers[2].Identifier)
	}
}
