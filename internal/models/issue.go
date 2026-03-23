package models

import "strings"

// Severity levels for issues.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// SeverityRank returns numeric rank for severity comparison.
func SeverityRank(s Severity) int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

// IssueReference points to a specific server/entity within a scan.
type IssueReference struct {
	ServerIndex int  `json:"server_index"`
	EntityIndex *int `json:"entity_index,omitempty"`
}

// Issue represents a security finding.
type Issue struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Reference *IssueReference `json:"reference,omitempty"`
	ExtraData map[string]any `json:"extra_data,omitempty"`
}

// GetSeverity returns the severity for this issue based on its code prefix.
func (i *Issue) GetSeverity() Severity {
	// Check for custom severity in extra_data
	if i.ExtraData != nil {
		if s, ok := i.ExtraData["severity"]; ok {
			if sv, ok := s.(string); ok {
				return Severity(sv)
			}
		}
	}

	code := i.Code
	switch {
	case strings.HasPrefix(code, "E"):
		return SeverityHigh
	case strings.HasPrefix(code, "W"):
		return SeverityMedium
	case strings.HasPrefix(code, "TF"):
		return SeverityHigh
	default:
		return SeverityInfo
	}
}

// Issue code constants.
const (
	// Critical (E-codes)
	CodePromptInjection      = "E001" // Prompt injection in tool description
	CodeCrossServerRef       = "E002" // Cross-server tool reference (tool shadowing)
	CodeBehaviorHijack       = "E003" // Tool description hijacks agent behavior
	CodeSkillInjection       = "E004" // Prompt injection in skill
	CodeSuspiciousURL        = "E005" // Suspicious download URL in skill
	CodeMaliciousCode        = "E006" // Malicious code patterns in skill

	// Warnings (W-codes)
	CodeSuspiciousWords      = "W001" // Suspicious trigger words
	CodeTooManyEntities      = "W002" // Too many entities (>100)
	CodeInsecureCredentials  = "W007" // Insecure credential handling
	CodeHardcodedSecrets     = "W008" // Hardcoded secrets
	CodeFinancialExecution   = "W009" // Direct financial execution
	CodeUntrustedContent     = "W011" // Untrusted third-party content exposure
	CodeExternalDependencies = "W012" // Unverifiable external dependencies
	CodeSystemModification   = "W013" // System service modification

	// Toxic Flows
	CodeDataLeakFlow         = "TF001" // Data leak flow
	CodeDestructiveFlow      = "TF002" // Destructive toxic flow

	// System codes
	CodeServerStartup        = "X001" // Server startup failure
	CodeSkillScanError       = "X002" // Skill scan error
	CodeFileNotFound         = "X003" // File not found
	CodeUnknownConfig        = "X004" // Unknown config format
	CodeParseError           = "X005" // Parse error
	CodeServerHTTPError      = "X006" // Server HTTP error
	CodeAnalysisError        = "X007" // Analysis error
	CodeUnknownError         = "X008" // Unknown error
)
