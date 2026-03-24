package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/go-authgate/agent-scanner/internal/models"
)

func intPtr(i int) *int { return &i }

func TestFormatResults_EntityIssuesDisplayed(t *testing.T) {
	results := []models.ScanPathResult{
		{
			Client: "test-client",
			Path:   "/test/path",
			Servers: []models.ServerScanResult{
				{
					Name: "test-server",
					Signature: &models.ServerSignature{
						Tools: []models.Tool{
							{Name: "read-file", Description: "Reads a file"},
						},
					},
				},
			},
			Issues: []models.Issue{
				{
					Code:    "E003",
					Message: "Behavior hijack detected",
					Reference: &models.IssueReference{
						ServerIndex: 0,
						EntityIndex: intPtr(0),
					},
				},
				{
					Code:    "W001",
					Message: "Suspicious trigger words",
					Reference: &models.IssueReference{
						ServerIndex: 0,
						EntityIndex: intPtr(0),
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	f := NewTextFormatter(&buf)
	err := f.FormatResults(results, FormatOptions{})
	if err != nil {
		t.Fatal(err)
	}

	output := buf.String()

	serverPos := strings.Index(output, "test-server")
	if serverPos == -1 {
		t.Fatal("expected server name 'test-server' in output")
	}

	e003Pos := strings.Index(output, "[E003] Behavior hijack detected")
	if e003Pos == -1 {
		t.Fatal("expected E003 issue to appear in output")
	}

	w001Pos := strings.Index(output, "[W001] Suspicious trigger words")
	if w001Pos == -1 {
		t.Fatal("expected W001 warning to appear in output")
	}

	// Entity issues must appear after their server header
	if serverPos >= e003Pos || serverPos >= w001Pos {
		t.Errorf("expected issues after server header; server=%d, E003=%d, W001=%d",
			serverPos, e003Pos, w001Pos)
	}

	// Issues must appear before the summary
	summaryPos := strings.Index(output, "1 issue(s) found")
	if summaryPos == -1 {
		t.Fatal("expected issue count in summary")
	}
	if e003Pos >= summaryPos {
		t.Errorf("expected E003 before summary; E003=%d, summary=%d", e003Pos, summaryPos)
	}

	if !strings.Contains(output, "1 warning(s)") {
		t.Error("expected warning count in summary")
	}
}

func TestFormatResults_GlobalIssuesDisplayed(t *testing.T) {
	results := []models.ScanPathResult{
		{
			Client: "test-client",
			Path:   "/test/path",
			Servers: []models.ServerScanResult{
				{
					Name: "server-a",
					Signature: &models.ServerSignature{
						Tools: []models.Tool{
							{Name: "tool-a", Description: "Tool A"},
						},
					},
				},
			},
			Issues: []models.Issue{
				{
					Code:    "TF001",
					Message: "Data leak flow detected",
				},
			},
		},
	}

	var buf bytes.Buffer
	f := NewTextFormatter(&buf)
	err := f.FormatResults(results, FormatOptions{})
	if err != nil {
		t.Fatal(err)
	}

	output := buf.String()

	if !strings.Contains(output, "[TF001] Data leak flow detected") {
		t.Error("expected TF001 global issue to appear in output")
	}
}

func TestFormatResults_MixedIssues(t *testing.T) {
	results := []models.ScanPathResult{
		{
			Client: "test-client",
			Path:   "/test/path",
			Servers: []models.ServerScanResult{
				{
					Name: "server-a",
					Signature: &models.ServerSignature{
						Tools: []models.Tool{
							{Name: "tool-a", Description: "Tool A"},
						},
					},
				},
			},
			Issues: []models.Issue{
				{
					Code:    "E004",
					Message: "Skill injection detected",
					Reference: &models.IssueReference{
						ServerIndex: 0,
						EntityIndex: intPtr(0),
					},
				},
				{
					Code:    "TF002",
					Message: "Destructive flow detected",
				},
			},
		},
	}

	var buf bytes.Buffer
	f := NewTextFormatter(&buf)
	err := f.FormatResults(results, FormatOptions{})
	if err != nil {
		t.Fatal(err)
	}

	output := buf.String()

	if !strings.Contains(output, "[E004] Skill injection detected") {
		t.Error("expected E004 entity issue to appear in output")
	}
	if !strings.Contains(output, "[TF002] Destructive flow detected") {
		t.Error("expected TF002 global issue to appear in output")
	}
	if !strings.Contains(output, "2 issue(s) found") {
		t.Error("expected 2 issues in summary")
	}
}

func TestFormatResults_ServerLevelReferencedIssue(t *testing.T) {
	results := []models.ScanPathResult{
		{
			Client: "test-client",
			Path:   "/test/path",
			Servers: []models.ServerScanResult{
				{
					Name: "big-server",
					Signature: &models.ServerSignature{
						Tools: []models.Tool{
							{Name: "tool-a", Description: "Tool A"},
						},
					},
				},
			},
			Issues: []models.Issue{
				{
					Code:    "W002",
					Message: "Too many entities exposed by this server",
					Reference: &models.IssueReference{
						ServerIndex: 0,
						EntityIndex: nil, // server-level, no specific entity
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	f := NewTextFormatter(&buf)
	err := f.FormatResults(results, FormatOptions{})
	if err != nil {
		t.Fatal(err)
	}

	output := buf.String()

	if !strings.Contains(output, "[W002] Too many entities exposed by this server") {
		t.Error("expected W002 server-level issue to appear in output")
	}
	if !strings.Contains(output, "1 warning(s)") {
		t.Error("expected warning count in summary")
	}
}

func TestFormatResults_NoIssues(t *testing.T) {
	results := []models.ScanPathResult{
		{
			Client: "test-client",
			Path:   "/test/path",
			Servers: []models.ServerScanResult{
				{
					Name: "clean-server",
					Signature: &models.ServerSignature{
						Tools: []models.Tool{
							{Name: "safe-tool", Description: "A safe tool"},
						},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	f := NewTextFormatter(&buf)
	err := f.FormatResults(results, FormatOptions{})
	if err != nil {
		t.Fatal(err)
	}

	output := buf.String()

	if !strings.Contains(output, "No issues found") {
		t.Error("expected 'No issues found' in summary")
	}
	if strings.Contains(output, "issue(s) found") {
		t.Error("should not contain issue count when no issues")
	}
}
