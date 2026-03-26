package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-authgate/agent-scanner/internal/models"
)

// ---------------------------------------------------------------------------
// TextFormatter tests
// ---------------------------------------------------------------------------

func TestTextFormatter_EmptyResults(t *testing.T) {
	var buf bytes.Buffer
	f := NewTextFormatter(&buf)

	if err := f.FormatResults(nil, FormatOptions{}); err != nil {
		t.Fatalf("FormatResults returned error: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "No MCP configurations found.") {
		t.Errorf("expected 'No MCP configurations found.' in output, got:\n%s", got)
	}
}

func TestTextFormatter_ServersAndIssues(t *testing.T) {
	results := []models.ScanPathResult{
		{
			Client: "cursor",
			Path:   "/home/user/.cursor/mcp.json",
			Servers: []models.ServerScanResult{
				{
					Name:   "my-server",
					Server: &models.StdioServer{Command: "node"},
					Signature: &models.ServerSignature{
						Tools: []models.Tool{
							{Name: "read_file", Description: "Reads a file"},
							{Name: "write_file", Description: "Writes a file"},
						},
					},
				},
			},
			Issues: []models.Issue{
				{Code: "E001", Message: "Prompt injection detected"},
			},
		},
	}

	var buf bytes.Buffer
	f := NewTextFormatter(&buf)
	if err := f.FormatResults(results, FormatOptions{}); err != nil {
		t.Fatalf("FormatResults returned error: %v", err)
	}
	out := buf.String()

	// Status icon for issues (E001 is high severity -> redCross)
	if !strings.Contains(out, redCross) {
		t.Error("expected red cross icon in output for high-severity issue")
	}
	// Server name
	if !strings.Contains(out, "my-server") {
		t.Error("expected server name 'my-server' in output")
	}
	// Entity count
	if !strings.Contains(out, "2 entities") {
		t.Error("expected '2 entities' in output")
	}
	// Issue code
	if !strings.Contains(out, "E001") {
		t.Error("expected issue code 'E001' in output")
	}
}

func TestTextFormatter_Summary(t *testing.T) {
	results := []models.ScanPathResult{
		{
			Client: "claude",
			Path:   "/path/a",
			Servers: []models.ServerScanResult{
				{
					Name:   "server-a",
					Server: &models.StdioServer{Command: "a"},
					Signature: &models.ServerSignature{
						Tools: []models.Tool{{Name: "t1"}},
					},
				},
				{
					Name:   "server-b",
					Server: &models.StdioServer{Command: "b"},
					Signature: &models.ServerSignature{
						Tools:   []models.Tool{{Name: "t2"}, {Name: "t3"}},
						Prompts: []models.Prompt{{Name: "p1"}},
					},
				},
			},
			Issues: []models.Issue{
				{Code: "E002", Message: "cross-server ref"},   // high
				{Code: "W001", Message: "suspicious trigger"}, // medium (warning)
			},
		},
	}

	var buf bytes.Buffer
	f := NewTextFormatter(&buf)
	if err := f.FormatResults(results, FormatOptions{}); err != nil {
		t.Fatalf("FormatResults returned error: %v", err)
	}
	out := buf.String()

	// Summary should show 2 servers, 4 entities (1 + 2 tools + 1 prompt)
	if !strings.Contains(out, "2 server(s)") {
		t.Errorf("expected '2 server(s)' in summary, got:\n%s", out)
	}
	if !strings.Contains(out, "4 entities") {
		t.Errorf("expected '4 entities' in summary, got:\n%s", out)
	}
	if !strings.Contains(out, "1 issue(s) found") {
		t.Errorf("expected '1 issue(s) found' in summary, got:\n%s", out)
	}
	if !strings.Contains(out, "1 warning(s)") {
		t.Errorf("expected '1 warning(s)' in summary, got:\n%s", out)
	}
}

func TestTextFormatter_NilSignature(t *testing.T) {
	results := []models.ScanPathResult{
		{
			Client: "vscode",
			Path:   "/path/to/config",
			Servers: []models.ServerScanResult{
				{
					Name:      "dead-server",
					Server:    &models.StdioServer{Command: "dead"},
					Signature: nil,
				},
			},
		},
	}

	var buf bytes.Buffer
	f := NewTextFormatter(&buf)
	if err := f.FormatResults(results, FormatOptions{}); err != nil {
		t.Fatalf("FormatResults returned error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "(no response)") {
		t.Errorf("expected '(no response)' for nil signature, got:\n%s", out)
	}
}

func TestTextFormatter_ServerError_PrintErrors(t *testing.T) {
	results := []models.ScanPathResult{
		{
			Client: "windsurf",
			Path:   "/path/to/config",
			Servers: []models.ServerScanResult{
				{
					Name:   "broken-server",
					Server: &models.StdioServer{Command: "broken"},
					Error: &models.ScanError{
						Message:  "connection refused",
						Category: models.ErrCatServerStartup,
					},
				},
			},
		},
	}

	// Without PrintErrors
	var buf bytes.Buffer
	f := NewTextFormatter(&buf)
	if err := f.FormatResults(results, FormatOptions{PrintErrors: false}); err != nil {
		t.Fatalf("FormatResults returned error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "connection refused") {
		t.Error("expected error message to be hidden when PrintErrors=false")
	}

	// With PrintErrors
	buf.Reset()
	f = NewTextFormatter(&buf)
	if err := f.FormatResults(results, FormatOptions{PrintErrors: true}); err != nil {
		t.Fatalf("FormatResults returned error: %v", err)
	}
	out = buf.String()
	if !strings.Contains(out, "connection refused") {
		t.Errorf("expected error message 'connection refused' when PrintErrors=true, got:\n%s", out)
	}
}

func TestTextFormatter_TruncatesLongDescriptions(t *testing.T) {
	longDesc := strings.Repeat("A", 300)
	results := []models.ScanPathResult{
		{
			Client: "cursor",
			Path:   "/path/to/config",
			Servers: []models.ServerScanResult{
				{
					Name:   "long-desc-server",
					Server: &models.StdioServer{Command: "node"},
					Signature: &models.ServerSignature{
						Tools: []models.Tool{
							{Name: "verbose-tool", Description: longDesc},
						},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	f := NewTextFormatter(&buf)
	if err := f.FormatResults(results, FormatOptions{PrintFullDescs: false}); err != nil {
		t.Fatalf("FormatResults returned error: %v", err)
	}
	out := buf.String()

	// Should be truncated to 200 chars + "..."
	if !strings.Contains(out, "...") {
		t.Error("expected truncation ellipsis '...' in output")
	}
	// The full 300-char string should NOT appear
	if strings.Contains(out, longDesc) {
		t.Error("expected description to be truncated, but found full 300-char string")
	}
	// First 200 chars should appear
	truncated := longDesc[:200]
	if !strings.Contains(out, truncated) {
		t.Error("expected first 200 chars of description to appear")
	}
}

// ---------------------------------------------------------------------------
// JSONFormatter tests
// ---------------------------------------------------------------------------

func TestJSONFormatter_ValidJSON(t *testing.T) {
	results := []models.ScanPathResult{
		{
			Client: "claude",
			Path:   "/path/to/config",
			Servers: []models.ServerScanResult{
				{
					Name:   "test-server",
					Server: &models.StdioServer{Command: "node"},
					Signature: &models.ServerSignature{
						Tools: []models.Tool{
							{Name: "hello", Description: "says hello"},
						},
					},
				},
			},
			Issues: []models.Issue{
				{Code: "W001", Message: "suspicious words"},
			},
		},
	}

	var buf bytes.Buffer
	f := NewJSONFormatter(&buf)
	if err := f.FormatResults(results, FormatOptions{}); err != nil {
		t.Fatalf("FormatResults returned error: %v", err)
	}

	var parsed []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\nraw output:\n%s", err, buf.String())
	}
	if len(parsed) != 1 {
		t.Errorf("expected 1 result in JSON array, got %d", len(parsed))
	}
}

func TestJSONFormatter_EmptyResults(t *testing.T) {
	var buf bytes.Buffer
	f := NewJSONFormatter(&buf)
	if err := f.FormatResults([]models.ScanPathResult{}, FormatOptions{}); err != nil {
		t.Fatalf("FormatResults returned error: %v", err)
	}

	got := strings.TrimSpace(buf.String())
	if got != "[]" {
		t.Errorf("expected '[]' for empty results, got: %s", got)
	}
}
