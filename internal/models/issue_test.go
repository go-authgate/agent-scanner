package models

import "testing"

func TestIssueSeverity(t *testing.T) {
	tests := []struct {
		code     string
		expected Severity
	}{
		{"E001", SeverityHigh},
		{"E003", SeverityCritical},
		{"E004", SeverityCritical},
		{"E006", SeverityHigh},
		{"W001", SeverityMedium},
		{"W013", SeverityMedium},
		{"TF001", SeverityHigh},
		{"TF002", SeverityHigh},
		{"X001", SeverityInfo},
		{"X008", SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			issue := Issue{Code: tt.code, Message: "test"}
			if got := issue.GetSeverity(); got != tt.expected {
				t.Errorf("Issue{Code: %q}.GetSeverity() = %q, want %q", tt.code, got, tt.expected)
			}
		})
	}
}

func TestIssueSeverityFromExtraData(t *testing.T) {
	issue := Issue{
		Code:      "W001",
		Message:   "test",
		ExtraData: map[string]any{"severity": "critical"},
	}
	if got := issue.GetSeverity(); got != SeverityCritical {
		t.Errorf("expected critical severity from extra_data, got %q", got)
	}
}

func TestSeverityRank(t *testing.T) {
	if SeverityRank(SeverityInfo) >= SeverityRank(SeverityLow) {
		t.Error("info should rank below low")
	}
	if SeverityRank(SeverityLow) >= SeverityRank(SeverityMedium) {
		t.Error("low should rank below medium")
	}
	if SeverityRank(SeverityMedium) >= SeverityRank(SeverityHigh) {
		t.Error("medium should rank below high")
	}
	if SeverityRank(SeverityHigh) >= SeverityRank(SeverityCritical) {
		t.Error("high should rank below critical")
	}
}
