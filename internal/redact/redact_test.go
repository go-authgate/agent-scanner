package redact

import (
	"strings"
	"testing"

	"github.com/go-authgate/agent-scanner/internal/models"
)

func TestAbsolutePaths(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"/Users/john/Documents/secret.txt", RedactedValue},
		{"C:\\Users\\john\\secret.txt", RedactedValue},
		{"~/Documents/secret.txt", RedactedValue},
	}

	for _, tt := range tests {
		result := AbsolutePaths(tt.input)
		if !strings.Contains(result, tt.contains) {
			t.Errorf(
				"AbsolutePaths(%q) = %q, expected to contain %q",
				tt.input,
				result,
				tt.contains,
			)
		}
	}
}

func TestServerResult_Stdio(t *testing.T) {
	result := &models.ServerScanResult{
		Server: &models.StdioServer{
			Command: "my-server",
			Args:    []string{"--config", "/home/user/secret.json"},
			Env:     map[string]string{"API_KEY": "sk-secret123"},
		},
	}

	ServerResult(result)

	stdio := result.Server.(*models.StdioServer)
	if stdio.Env["API_KEY"] != RedactedValue {
		t.Errorf("expected env redacted, got %s", stdio.Env["API_KEY"])
	}
	if stdio.Args[1] != RedactedValue {
		t.Errorf("expected path arg redacted, got %s", stdio.Args[1])
	}
}

func TestServerResult_Remote(t *testing.T) {
	result := &models.ServerScanResult{
		Server: &models.RemoteServer{
			URL:     "https://example.com/mcp?token=secret123",
			Headers: map[string]string{"Authorization": "Bearer my-token"},
		},
	}

	ServerResult(result)

	remote := result.Server.(*models.RemoteServer)
	if remote.Headers["Authorization"] != RedactedValue {
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
		if got := IsPath(tt.arg); got != tt.expected {
			t.Errorf("IsPath(%q) = %v, want %v", tt.arg, got, tt.expected)
		}
	}
}

func TestLooksLikeSecret(t *testing.T) {
	positives := []string{
		"sk-abc123",             // OpenAI
		"sk-ant-api03-abc",      // Anthropic
		"ghp_abcdef1234567890",  // GitHub PAT
		"gho_token",             // GitHub OAuth
		"github_pat_abc",        // GitHub fine-grained
		"Bearer my-token",       // Bearer token
		"AKIAIOSFODNN7EXAMPLE",  // AWS access key
		"xoxb-slack-bot-token",  // Slack bot
		"xoxp-slack-user-token", // Slack user
		"xapp-slack-app-token",  // Slack app
		"glpat-xxxxxxxxxxxx",    // GitLab PAT
		"npm_xxxxxxxx",          // npm token
		"pypi-AgEIcHlwaS5vcmc",  // PyPI token
		"whsec_abcdef123456",    // Stripe webhook
		"sk_live_abc123",        // Stripe live key
		"sk_test_abc123",        // Stripe test key
		"rk_live_abc123",        // Stripe restricted
		"AGE-SECRET-KEY-1abc",   // age key
	}

	for _, s := range positives {
		if !LooksLikeSecret(s) {
			t.Errorf("LooksLikeSecret(%q) = false, want true", s)
		}
	}

	negatives := []string{
		"--port",
		"8080",
		"localhost",
		"my-server",
		"true",
		"",
		"short",
	}

	for _, s := range negatives {
		if LooksLikeSecret(s) {
			t.Errorf("LooksLikeSecret(%q) = true, want false", s)
		}
	}
}

func TestLooksLikeSecret_HighEntropy(t *testing.T) {
	// Long mixed-case alphanumeric string should be detected
	if !LooksLikeSecret("aB3cD4eF5gH6iJ7kL8mN9oP") {
		t.Error("expected high-entropy string to be detected as secret")
	}

	// Short string should not trigger entropy heuristic
	if LooksLikeSecret("aB3c") {
		t.Error("short mixed-case string should not be detected")
	}

	// String with spaces should not trigger
	if LooksLikeSecret("this Is A Regular Sentence 123") {
		t.Error("string with spaces should not trigger entropy heuristic")
	}
}
