package rules

import "github.com/go-authgate/agent-scanner/internal/models"

type labeledTool struct {
	serverIdx int
	toolIdx   int
	name      string
	server    string
}

// DataLeakFlow checks for TF001: data leak toxic flows.
type DataLeakFlow struct{}

func (r *DataLeakFlow) Code() string { return models.CodeDataLeakFlow }
func (r *DataLeakFlow) Name() string { return "data_leak_flow" }

func (r *DataLeakFlow) Check(ctx *RuleContext) []models.Issue {
	if ctx.Labels == nil {
		return nil
	}

	var issues []models.Issue
	var untrustedSources, privateDataTools, publicSinks []labeledTool

	for si, server := range ctx.Servers {
		if server.Signature == nil || si >= len(ctx.Labels) {
			continue
		}
		for ti, tool := range server.Signature.Tools {
			if ti >= len(ctx.Labels[si]) {
				continue
			}
			labels := ctx.Labels[si][ti]
			lt := labeledTool{serverIdx: si, toolIdx: ti, name: tool.Name, server: server.Name}

			if labels.UntrustedContent > 0.5 {
				untrustedSources = append(untrustedSources, lt)
			}
			if labels.PrivateData > 0.5 {
				privateDataTools = append(privateDataTools, lt)
			}
			if labels.IsPublicSink > 0.5 {
				publicSinks = append(publicSinks, lt)
			}
		}
	}

	if len(untrustedSources) > 0 && len(privateDataTools) > 0 && len(publicSinks) > 0 {
		for _, source := range untrustedSources {
			for _, sink := range publicSinks {
				issues = append(issues, models.Issue{
					Code:    models.CodeDataLeakFlow,
					Message: "Data leak toxic flow detected: untrusted content sources combined with private data access and public sinks enable potential data exfiltration",
					ExtraData: map[string]any{
						"source_server": source.server,
						"source_tool":   source.name,
						"sink_server":   sink.server,
						"sink_tool":     sink.name,
						"private_tools": labeledToolNames(privateDataTools),
						"flow_type":     "data_leak",
					},
				})
			}
		}
	}

	return issues
}

// DestructiveFlow checks for TF002: destructive toxic flows.
type DestructiveFlow struct{}

func (r *DestructiveFlow) Code() string { return models.CodeDestructiveFlow }
func (r *DestructiveFlow) Name() string { return "destructive_flow" }

func (r *DestructiveFlow) Check(ctx *RuleContext) []models.Issue {
	if ctx.Labels == nil {
		return nil
	}

	var issues []models.Issue
	var untrustedSources, destructiveTools []labeledTool

	for si, server := range ctx.Servers {
		if server.Signature == nil || si >= len(ctx.Labels) {
			continue
		}
		for ti, tool := range server.Signature.Tools {
			if ti >= len(ctx.Labels[si]) {
				continue
			}
			labels := ctx.Labels[si][ti]
			lt := labeledTool{serverIdx: si, toolIdx: ti, name: tool.Name, server: server.Name}

			if labels.UntrustedContent > 0.5 {
				untrustedSources = append(untrustedSources, lt)
			}
			if labels.Destructive > 0.5 {
				destructiveTools = append(destructiveTools, lt)
			}
		}
	}

	if len(untrustedSources) > 0 && len(destructiveTools) > 0 {
		for _, source := range untrustedSources {
			for _, dest := range destructiveTools {
				issues = append(issues, models.Issue{
					Code:    models.CodeDestructiveFlow,
					Message: "Destructive toxic flow detected: untrusted content sources combined with irreversible destructive capabilities",
					ExtraData: map[string]any{
						"source_server":      source.server,
						"source_tool":        source.name,
						"destructive_server": dest.server,
						"destructive_tool":   dest.name,
						"flow_type":          "destructive",
					},
				})
			}
		}
	}

	return issues
}

func labeledToolNames(tools []labeledTool) []string {
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = t.name
	}
	return names
}
