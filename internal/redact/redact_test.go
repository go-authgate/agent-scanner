package redact

import (
	"strings"
	"testing"

	"github.com/go-authgate/agent-scanner/internal/models"
)

func TestRedactAbsolutePaths(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"/Users/john/Documents/secret.txt", redactedValue},
		{"C:\\Users\\john\\secret.txt", redactedValue},
		{"~/Documents/secret.txt", redactedValue},
	}

	for _, tt := range tests {
		result := RedactAbsolutePaths(tt.input)
		if !strings.Contains(result, tt.contains) {
			t.Errorf("RedactAbsolutePaths(%q) = %q, expected to contain %q", tt.input, result, tt.contains)
		}
	}
}

func TestRedactServerResult_Stdio(t *testing.T) {
	result := &models.ServerScanResult{
		Server: &models.StdioServer{
			Command: "my-server",
			Args:    []string{"--config", "/home/user/secret.json"},
			Env:     map[string]string{"API_KEY": "sk-secret123"},
		},
	}

	RedactServerResult(result)

	stdio := result.Server.(*models.StdioServer)
	if stdio.Env["API_KEY"] != redactedValue {
		t.Errorf("expected env redacted, got %s", stdio.Env["API_KEY"])
	}
	if stdio.Args[1] != redactedValue {
		t.Errorf("expected path arg redacted, got %s", stdio.Args[1])
	}
}

func TestRedactServerResult_Remote(t *testing.T) {
	result := &models.ServerScanResult{
		Server: &models.RemoteServer{
			URL:     "https://example.com/mcp?token=secret123",
			Headers: map[string]string{"Authorization": "Bearer my-token"},
		},
	}

	RedactServerResult(result)

	remote := result.Server.(*models.RemoteServer)
	if remote.Headers["Authorization"] != redactedValue {
		t.Errorf("expected header redacted, got %s", remote.Headers["Authorization"])
	}
	if strings.Contains(remote.URL, "secret123") {
		t.Error("expected query parameter redacted")
	}
}

func TestIsPath(t *testing.T) {
	tests := []struct {
		arg      string
		expected bool
	}{
		{"/etc/config", true},
		{"~/config", true},
		{"C:\\Windows", true},
		{"--flag", false},
		{"value", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := isPath(tt.arg); got != tt.expected {
			t.Errorf("isPath(%q) = %v, want %v", tt.arg, got, tt.expected)
		}
	}
}
