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

func TestParseControlServers_WithHeaders(t *testing.T) {
	orig := scanFlags
	defer func() { scanFlags = orig }()

	scanFlags = ScanFlags{
		ControlServers: []string{"https://a.example.com", "https://b.example.com"},
		ControlHeaders: []string{"Authorization: Bearer token123; X-Custom: value"},
	}

	servers := parseControlServers()
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	if servers[0].Headers == nil {
		t.Fatal("expected headers for server[0]")
	}
	if servers[0].Headers["Authorization"] != "Bearer token123" {
		t.Errorf(
			"Authorization = %q, want %q",
			servers[0].Headers["Authorization"],
			"Bearer token123",
		)
	}
	if servers[0].Headers["X-Custom"] != "value" {
		t.Errorf("X-Custom = %q, want %q", servers[0].Headers["X-Custom"], "value")
	}

	// server[1] has no matching header entry
	if servers[1].Headers != nil {
		t.Errorf("expected nil headers for server[1], got %v", servers[1].Headers)
	}
}

func TestParseHeaders(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{
			name: "single header",
			raw:  "Authorization: Bearer abc",
			want: map[string]string{"Authorization": "Bearer abc"},
		},
		{
			name: "multiple headers",
			raw:  "Key1: Val1; Key2: Val2",
			want: map[string]string{"Key1": "Val1", "Key2": "Val2"},
		},
		{
			name: "empty string",
			raw:  "",
			want: nil,
		},
		{
			name: "whitespace only",
			raw:  "  ;  ",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHeaders(tt.raw)
			if tt.want == nil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("header %q = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}
