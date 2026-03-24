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

	if !strings.Contains(output, "[E003] Behavior hijack detected") {
		t.Error("expected E003 issue to appear in output")
	}
	if !strings.Contains(output, "[W001] Suspicious trigger words") {
		t.Error("expected W001 warning to appear in output")
	}
	if !strings.Contains(output, "1 issue(s) found") {
		t.Error("expected issue count in summary")
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
