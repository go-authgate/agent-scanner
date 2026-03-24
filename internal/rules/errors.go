package rules

import (
	"strings"

	"github.com/go-authgate/agent-scanner/internal/models"
)

// CrossServerReference checks for E002: cross-server tool references (tool shadowing).
type CrossServerReference struct{}

func (r *CrossServerReference) Code() string { return models.CodeCrossServerRef }
func (r *CrossServerReference) Name() string { return "cross_server_reference" }

func (r *CrossServerReference) Check(ctx *RuleContext) []models.Issue {
	var issues []models.Issue

	// Build a map of all tool names by server
	toolsByServer := make(map[int]map[string]bool)
	for si, server := range ctx.Servers {
		if server.Signature == nil {
			continue
		}
		toolsByServer[si] = make(map[string]bool)
		for _, tool := range server.Signature.Tools {
			toolsByServer[si][strings.ToLower(tool.Name)] = true
		}
	}

	// Check if any tool description references tools from other servers
	for _, ie := range ctx.AllEntities() {
		desc := strings.ToLower(ie.Entity.GetDescription())
		for otherSI, otherTools := range toolsByServer {
			if otherSI == ie.ServerIndex {
				continue
			}
			for toolName := range otherTools {
				if strings.Contains(desc, toolName) {
					ei := ie.EntityIndex
					issues = append(issues, models.Issue{
						Code:    models.CodeCrossServerRef,
						Message: "Tool description references tools from another MCP server, potentially enabling tool shadowing attacks",
						Reference: &models.IssueReference{
							ServerIndex: ie.ServerIndex,
							EntityIndex: &ei,
						},
						ExtraData: map[string]any{
							"referenced_tool":   toolName,
							"referenced_server": otherSI,
						},
					})
				}
			}
		}
	}

	return issues
}

// MaliciousCodePatterns checks for E006: malicious code patterns.
type MaliciousCodePatterns struct{}

func (r *MaliciousCodePatterns) Code() string { return models.CodeMaliciousCode }
func (r *MaliciousCodePatterns) Name() string { return "malicious_code_patterns" }

func (r *MaliciousCodePatterns) Check(ctx *RuleContext) []models.Issue {
	var issues []models.Issue
	for _, ie := range ctx.AllEntities() {
		desc := ie.Entity.GetDescription()
		for _, pattern := range maliciousCodePatterns {
			if pattern.MatchString(desc) {
				ei := ie.EntityIndex
				issues = append(issues, models.Issue{
					Code:    models.CodeMaliciousCode,
					Message: "High-risk code patterns detected including potential data exfiltration, backdoors, or remote code execution",
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

// BehaviorHijack checks for E003: overt agent behavior hijacking in tool/prompt descriptions.
type BehaviorHijack struct{}

func (r *BehaviorHijack) Code() string { return models.CodeBehaviorHijack }
func (r *BehaviorHijack) Name() string { return "behavior_hijack" }

func (r *BehaviorHijack) Check(ctx *RuleContext) []models.Issue {
	var issues []models.Issue
	for _, ie := range ctx.AllEntities() {
		// Only check tools and prompts — resources don't carry behavioral instructions.
		if ie.Entity.Kind() != models.EntityKindTool &&
			ie.Entity.Kind() != models.EntityKindPrompt {
			continue
		}
		desc := strings.ToLower(ie.Entity.GetDescription())
		for _, pattern := range behaviorHijackPatterns {
			if strings.Contains(desc, pattern) {
				ei := ie.EntityIndex
				issues = append(issues, models.Issue{
					Code:    models.CodeBehaviorHijack,
					Message: "Entity description contains overt instructions attempting to hijack agent behavior or override safety guidelines",
					Reference: &models.IssueReference{
						ServerIndex: ie.ServerIndex,
						EntityIndex: &ei,
					},
					ExtraData: map[string]any{"pattern": pattern},
				})
				break
			}
		}
	}
	return issues
}

// SkillInjection checks for E004: prompt injection hidden in skill content.
type SkillInjection struct{}

func (r *SkillInjection) Code() string { return models.CodeSkillInjection }
func (r *SkillInjection) Name() string { return "skill_injection" }

func (r *SkillInjection) Check(ctx *RuleContext) []models.Issue {
	var issues []models.Issue
	for si, server := range ctx.Servers {
		if server.Server == nil || server.Server.GetServerType() != models.ServerTypeSkill {
			continue
		}
		if server.Signature == nil {
			continue
		}
		for ei, entity := range server.Signature.Entities() {
			desc := strings.ToLower(entity.GetDescription())
			for _, word := range suspiciousTriggerWords {
				if strings.Contains(desc, strings.ToLower(word)) {
					eiCopy := ei
					issues = append(issues, models.Issue{
						Code:    models.CodeSkillInjection,
						Message: "Skill content contains hidden or deceptive instructions designed to override agent safety guidelines",
						Reference: &models.IssueReference{
							ServerIndex: si,
							EntityIndex: &eiCopy,
						},
						ExtraData: map[string]any{"word": word},
					})
					break
				}
			}
		}
	}
	return issues
}

// SuspiciousURLs checks for E005: suspicious download URLs.
type SuspiciousURLs struct{}

func (r *SuspiciousURLs) Code() string { return models.CodeSuspiciousURL }
func (r *SuspiciousURLs) Name() string { return "suspicious_urls" }

func (r *SuspiciousURLs) Check(ctx *RuleContext) []models.Issue {
	var issues []models.Issue
	for _, ie := range ctx.AllEntities() {
		desc := ie.Entity.GetDescription()
		for _, pattern := range suspiciousURLPatterns {
			if pattern.MatchString(desc) {
				ei := ie.EntityIndex
				issues = append(issues, models.Issue{
					Code:    models.CodeSuspiciousURL,
					Message: "Suspicious URL pointing to untrusted executable sources, URL shorteners, or personal file hosting",
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
