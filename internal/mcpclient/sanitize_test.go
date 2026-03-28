package mcpclient

import (
	"strings"
	"testing"
)

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		checks func(t *testing.T, result string)
	}{
		{
			name:  "no query params",
			input: "https://example.com/mcp",
			checks: func(t *testing.T, result string) {
				if result != "https://example.com/mcp" {
					t.Errorf("got %s, want unchanged", result)
				}
			},
		},
		{
			name:  "query params redacted",
			input: "https://example.com/mcp?token=secret123&key=abc",
			checks: func(t *testing.T, result string) {
				if strings.Contains(result, "secret123") {
					t.Error("token value not redacted")
				}
				if strings.Contains(result, "abc") {
					t.Error("key value not redacted")
				}
				if !strings.Contains(result, "token=") {
					t.Error("token key should be preserved")
				}
			},
		},
		{
			name:  "invalid URL returned as-is",
			input: "://invalid",
			checks: func(t *testing.T, result string) {
				if result != "://invalid" {
					t.Errorf("got %s, want unchanged for invalid URL", result)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeURL(tt.input)
			tt.checks(t, result)
		})
	}
}

func TestSanitizeArgs(t *testing.T) {
	args := []string{
		"--config",
		"/home/user/secret.json",
		"sk-abc123",
		"--port",
		"8080",
	}

	result := sanitizeArgs(args)

	if result[0] != "--config" {
		t.Errorf("expected --config, got %s", result[0])
	}
	if result[1] != "**REDACTED**" {
		t.Errorf("expected path redacted, got %s", result[1])
	}
	if result[2] != "**REDACTED**" {
		t.Errorf("expected secret redacted, got %s", result[2])
	}
	if result[3] != "--port" {
		t.Errorf("expected --port, got %s", result[3])
	}
	if result[4] != "8080" {
		t.Errorf("expected 8080, got %s", result[4])
	}

	// Verify original args not modified
	if args[1] != "/home/user/secret.json" {
		t.Error("original args should not be modified")
	}
}
