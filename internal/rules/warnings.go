package rules

import (
	"strings"

	"github.com/go-authgate/agent-scanner/internal/models"
)

// SuspiciousTriggerWords checks for W001: suspicious trigger words in descriptions.
type SuspiciousTriggerWords struct{}

func (r *SuspiciousTriggerWords) Code() string { return models.CodeSuspiciousWords }
func (r *SuspiciousTriggerWords) Name() string { return "suspicious_trigger_words" }

func (r *SuspiciousTriggerWords) Check(ctx *RuleContext) []models.Issue {
	var issues []models.Issue
	for _, ie := range ctx.AllEntities() {
		desc := strings.ToLower(ie.Entity.GetDescription())
		var found []string
		for _, word := range suspiciousTriggerWords {
			if strings.Contains(desc, word) {
				found = append(found, word)
			}
		}
		if len(found) > 0 {
			ei := ie.EntityIndex
			issues = append(issues, models.Issue{
				Code:    models.CodeSuspiciousWords,
				Message: "Tool description contains suspicious trigger words commonly used in prompt injection attacks",
				Reference: &models.IssueReference{
					ServerIndex: ie.ServerIndex,
					EntityIndex: &ei,
				},
				ExtraData: map[string]any{"words": found},
			})
		}
	}
	return issues
}

// TooManyEntities checks for W002: too many entities.
type TooManyEntities struct{}

func (r *TooManyEntities) Code() string { return models.CodeTooManyEntities }
func (r *TooManyEntities) Name() string { return "too_many_entities" }

func (r *TooManyEntities) Check(ctx *RuleContext) []models.Issue {
	var issues []models.Issue
	for si, server := range ctx.Servers {
		if server.Signature == nil {
			continue
		}
		count := server.Signature.EntityCount()
		if count > 100 {
			issues = append(issues, models.Issue{
				Code:    models.CodeTooManyEntities,
				Message: "Server exposes over 100 combined entities, degrading agent performance and expanding attack surface",
				Reference: &models.IssueReference{
					ServerIndex: si,
				},
				ExtraData: map[string]any{"count": count},
			})
		}
	}
	return issues
}

// HardcodedSecrets checks for W008: hardcoded secrets in descriptions.
type HardcodedSecrets struct{}

func (r *HardcodedSecrets) Code() string { return models.CodeHardcodedSecrets }
func (r *HardcodedSecrets) Name() string { return "hardcoded_secrets" }

func (r *HardcodedSecrets) Check(ctx *RuleContext) []models.Issue {
	var issues []models.Issue
	for _, ie := range ctx.AllEntities() {
		desc := ie.Entity.GetDescription()
		for _, pattern := range secretPatterns {
			if pattern.MatchString(desc) {
				ei := ie.EntityIndex
				issues = append(issues, models.Issue{
					Code:    models.CodeHardcodedSecrets,
					Message: "Hardcoded sensitive credentials found in entity description",
					Reference: &models.IssueReference{
						ServerIndex: ie.ServerIndex,
						EntityIndex: &ei,
					},
				})
				break
			}
		}
	}
	return issues
}

// InsecureCredentials checks for W007: insecure credential handling.
type InsecureCredentials struct{}

func (r *InsecureCredentials) Code() string { return models.CodeInsecureCredentials }
func (r *InsecureCredentials) Name() string { return "insecure_credentials" }

func (r *InsecureCredentials) Check(ctx *RuleContext) []models.Issue {
	var issues []models.Issue
	for _, ie := range ctx.AllEntities() {
		desc := strings.ToLower(ie.Entity.GetDescription())
		for _, keyword := range credentialKeywords {
			if strings.Contains(desc, keyword) {
				ei := ie.EntityIndex
				issues = append(issues, models.Issue{
					Code:    models.CodeInsecureCredentials,
					Message: "Entity requires agents to include credentials verbatim in output, exposing secrets",
					Reference: &models.IssueReference{
						ServerIndex: ie.ServerIndex,
						EntityIndex: &ei,
					},
				})
				break
			}
		}
	}
	return issues
}

// FinancialExecution checks for W009: direct financial execution.
type FinancialExecution struct{}

func (r *FinancialExecution) Code() string { return models.CodeFinancialExecution }
func (r *FinancialExecution) Name() string { return "financial_execution" }

func (r *FinancialExecution) Check(ctx *RuleContext) []models.Issue {
	var issues []models.Issue
	for _, ie := range ctx.AllEntities() {
		desc := strings.ToLower(ie.Entity.GetDescription())
		for _, keyword := range financialKeywords {
			if strings.Contains(desc, keyword) {
				ei := ie.EntityIndex
				issues = append(issues, models.Issue{
					Code:    models.CodeFinancialExecution,
					Message: "Entity enables direct financial transactions without proper safeguards",
					Reference: &models.IssueReference{
						ServerIndex: ie.ServerIndex,
						EntityIndex: &ei,
					},
				})
				break
			}
		}
	}
	return issues
}

// UntrustedContent checks for W011: untrusted third-party content exposure.
type UntrustedContent struct{}

func (r *UntrustedContent) Code() string { return models.CodeUntrustedContent }
func (r *UntrustedContent) Name() string { return "untrusted_content" }

func (r *UntrustedContent) Check(ctx *RuleContext) []models.Issue {
	var issues []models.Issue
	for _, ie := range ctx.AllEntities() {
		desc := ie.Entity.GetDescription()
		for _, pattern := range untrustedContentPatterns {
			if pattern.MatchString(desc) {
				ei := ie.EntityIndex
				issues = append(issues, models.Issue{
					Code:    models.CodeUntrustedContent,
					Message: "Entity exposes untrusted, user-generated third-party content creating indirect injection risks",
					Reference: &models.IssueReference{
						ServerIndex: ie.ServerIndex,
						EntityIndex: &ei,
					},
				})
				break
			}
		}
	}
	return issues
}

// ExternalDependencies checks for W012: unverifiable external dependencies.
type ExternalDependencies struct{}

func (r *ExternalDependencies) Code() string { return models.CodeExternalDependencies }
func (r *ExternalDependencies) Name() string { return "external_dependencies" }

func (r *ExternalDependencies) Check(ctx *RuleContext) []models.Issue {
	var issues []models.Issue
	for _, ie := range ctx.AllEntities() {
		desc := ie.Entity.GetDescription()
		for _, pattern := range externalDependencyPatterns {
			if pattern.MatchString(desc) {
				ei := ie.EntityIndex
				issues = append(issues, models.Issue{
					Code:    models.CodeExternalDependencies,
					Message: "Entity fetches instructions from external URLs at runtime, bypassing version control",
					Reference: &models.IssueReference{
						ServerIndex: ie.ServerIndex,
						EntityIndex: &ei,
					},
				})
				break
			}
		}
	}
	return issues
}

// SystemModification checks for W013: system service modification.
type SystemModification struct{}

func (r *SystemModification) Code() string { return models.CodeSystemModification }
func (r *SystemModification) Name() string { return "system_modification" }

func (r *SystemModification) Check(ctx *RuleContext) []models.Issue {
	var issues []models.Issue
	for _, ie := range ctx.AllEntities() {
		desc := strings.ToLower(ie.Entity.GetDescription())
		for _, keyword := range systemModKeywords {
			if strings.Contains(desc, keyword) {
				ei := ie.EntityIndex
				issues = append(issues, models.Issue{
					Code:    models.CodeSystemModification,
					Message: "Entity prompts system-level modifications affecting machine security or integrity",
					Reference: &models.IssueReference{
						ServerIndex: ie.ServerIndex,
						EntityIndex: &ei,
					},
				})
				break
			}
		}
	}
	return issues
}
