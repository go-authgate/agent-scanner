package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/go-authgate/agent-scanner/internal/models"
)

type textFormatter struct {
	writer io.Writer
}

// NewTextFormatter creates a colored text output formatter.
func NewTextFormatter(w io.Writer) Formatter {
	return &textFormatter{writer: w}
}

func (f *textFormatter) FormatResults(results []models.ScanPathResult, opts FormatOptions) error {
	if len(results) == 0 {
		fmt.Fprintln(f.writer, "No MCP configurations found.")
		return nil
	}

	for i, result := range results {
		f.formatPathResult(result, opts)
		if i < len(results)-1 {
			fmt.Fprintln(f.writer)
		}
	}

	// Print summary
	f.printSummary(results)

	return nil
}

func (f *textFormatter) formatPathResult(result models.ScanPathResult, opts FormatOptions) {
	// Path header
	clientLabel := result.Client
	if clientLabel == "" {
		clientLabel = "unknown"
	}

	issueCount, warnCount := countIssues(result.Issues)
	statusIcon := greenCheck
	if issueCount > 0 {
		statusIcon = redCross
	} else if warnCount > 0 {
		statusIcon = yellowWarn
	}

	fmt.Fprintf(f.writer, "%s %s (%s)\n", statusIcon, result.Path, clientLabel)

	// Path-level error
	if result.Error != nil {
		fmt.Fprintf(f.writer, "  %s Error: %s\n", redCross, result.Error.Message)
		return
	}

	// Servers
	for si, server := range result.Servers {
		f.formatServer(server, opts, result.Issues, si)
	}

	// Global issues (toxic flows, etc.)
	for _, issue := range result.Issues {
		if issue.Reference == nil {
			f.formatGlobalIssue(issue)
		}
	}
}

func (f *textFormatter) formatServer(
	server models.ServerScanResult,
	opts FormatOptions,
	issues []models.Issue,
	serverIndex int,
) {
	name := server.Name
	if name == "" {
		name = "(unnamed)"
	}

	if server.Error != nil {
		fmt.Fprintf(f.writer, "  %s %s\n", grayDot, name)
		if opts.PrintErrors {
			fmt.Fprintf(f.writer, "    Error: %s\n", server.Error.Message)
			if server.Error.Traceback != "" {
				fmt.Fprintf(f.writer, "    %s\n", server.Error.Traceback)
			}
		}
		return
	}

	if server.Signature == nil {
		fmt.Fprintf(f.writer, "  %s %s (no response)\n", grayDot, name)
		return
	}

	entityCount := server.Signature.EntityCount()
	fmt.Fprintf(f.writer, "  %s %s (%d entities)\n", greenCheck, name, entityCount)

	// List entities
	for _, entity := range server.Signature.Entities() {
		f.formatEntity(entity, opts)
	}

	// Server-scoped issues (entity-level and server-level) for this server
	for _, issue := range issues {
		if issue.Reference != nil && issue.Reference.ServerIndex == serverIndex {
			if issue.Reference.EntityIndex != nil {
				f.formatEntityIssue(issue)
			} else {
				f.formatServerIssue(issue)
			}
		}
	}
}

func (f *textFormatter) formatEntity(entity models.Entity, opts FormatOptions) {
	kind := entityKindLabel(entity.Kind())
	desc := entity.GetDescription()

	if !opts.PrintFullDescs && len(desc) > 200 {
		desc = desc[:200] + "..."
	}

	// Escape newlines for display
	desc = strings.ReplaceAll(desc, "\n", " ")

	fmt.Fprintf(f.writer, "    %s %s: %s\n", kind, entity.GetName(), desc)
}

func (f *textFormatter) formatScopedIssue(issue models.Issue, indent string) {
	severity := issue.GetSeverity()
	icon := severityIcon(severity)
	fmt.Fprintf(f.writer, "%s%s [%s] %s\n", indent, icon, issue.Code, issue.Message)
}

func (f *textFormatter) formatEntityIssue(issue models.Issue) {
	f.formatScopedIssue(issue, "    ")
}

func (f *textFormatter) formatServerIssue(issue models.Issue) {
	f.formatScopedIssue(issue, "    ")
}

func (f *textFormatter) formatGlobalIssue(issue models.Issue) {
	f.formatScopedIssue(issue, "  ")
}

func (f *textFormatter) printSummary(results []models.ScanPathResult) {
	totalServers := 0
	totalEntities := 0
	totalIssues := 0
	totalWarnings := 0

	for _, result := range results {
		totalServers += len(result.Servers)
		for _, server := range result.Servers {
			if server.Signature != nil {
				totalEntities += server.Signature.EntityCount()
			}
		}
		issues, warnings := countIssues(result.Issues)
		totalIssues += issues
		totalWarnings += warnings
	}

	fmt.Fprintf(f.writer, "\n─────────────────────────────────────────\n")
	fmt.Fprintf(f.writer, "Scanned %d server(s), %d entities\n", totalServers, totalEntities)
	if totalIssues > 0 {
		fmt.Fprintf(f.writer, "%s %d issue(s) found\n", redCross, totalIssues)
	}
	if totalWarnings > 0 {
		fmt.Fprintf(f.writer, "%s %d warning(s)\n", yellowWarn, totalWarnings)
	}
	if totalIssues == 0 && totalWarnings == 0 {
		fmt.Fprintf(f.writer, "%s No issues found\n", greenCheck)
	}
}

func countIssues(issues []models.Issue) (int, int) {
	var issueCount, warnCount int
	for _, issue := range issues {
		switch issue.GetSeverity() {
		case models.SeverityHigh, models.SeverityCritical:
			issueCount++
		case models.SeverityMedium:
			warnCount++
		}
	}
	return issueCount, warnCount
}

func entityKindLabel(kind models.EntityKind) string {
	switch kind {
	case models.EntityKindTool:
		return "[tool]"
	case models.EntityKindPrompt:
		return "[prompt]"
	case models.EntityKindResource:
		return "[resource]"
	case models.EntityKindResourceTemplate:
		return "[template]"
	default:
		return "[unknown]"
	}
}

func severityIcon(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return redCross
	case models.SeverityMedium:
		return yellowWarn
	default:
		return blueDot
	}
}

// Terminal symbols (ASCII fallback).
const (
	greenCheck = "✓"
	redCross   = "✗"
	yellowWarn = "⚠"
	grayDot    = "○"
	blueDot    = "ℹ"
)
