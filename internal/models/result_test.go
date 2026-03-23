package models

import "testing"

func TestServerSignatureEntities(t *testing.T) {
	sig := ServerSignature{
		Tools:     []Tool{{Name: "t1"}, {Name: "t2"}},
		Prompts:   []Prompt{{Name: "p1"}},
		Resources: []Resource{{Name: "r1"}},
		ResourceTemplates: []ResourceTemplate{{Name: "rt1"}},
	}

	entities := sig.Entities()
	if len(entities) != 5 {
		t.Errorf("expected 5 entities, got %d", len(entities))
	}

	if sig.EntityCount() != 5 {
		t.Errorf("expected EntityCount=5, got %d", sig.EntityCount())
	}
}

func TestScanPathResultHasIssues(t *testing.T) {
	tests := []struct {
		name     string
		issues   []Issue
		expected bool
	}{
		{
			name:     "no issues",
			issues:   nil,
			expected: false,
		},
		{
			name:     "info only",
			issues:   []Issue{{Code: "X001", Message: "test"}},
			expected: false,
		},
		{
			name:     "warning",
			issues:   []Issue{{Code: "W001", Message: "test"}},
			expected: true,
		},
		{
			name:     "critical",
			issues:   []Issue{{Code: "E001", Message: "test"}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ScanPathResult{Issues: tt.issues}
			if got := result.HasIssues(); got != tt.expected {
				t.Errorf("HasIssues() = %v, want %v", got, tt.expected)
			}
		})
	}
}
