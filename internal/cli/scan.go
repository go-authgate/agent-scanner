package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/go-authgate/agent-scanner/internal/analysis"
	"github.com/go-authgate/agent-scanner/internal/discovery"
	"github.com/go-authgate/agent-scanner/internal/inspect"
	"github.com/go-authgate/agent-scanner/internal/mcpclient"
	"github.com/go-authgate/agent-scanner/internal/output"
	"github.com/go-authgate/agent-scanner/internal/pipeline"
	"github.com/go-authgate/agent-scanner/internal/rules"
	"github.com/go-authgate/agent-scanner/internal/upload"
	"github.com/go-authgate/agent-scanner/internal/version"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [paths...]",
		Short: "Scan MCP servers and skills for security issues",
		Long:  "Scan discovers MCP servers from installed AI agents and analyzes them for prompt injections, tool poisoning, toxic flows, and other security threats.",
		RunE:  runScan,
	}
	addCommonFlags(cmd)
	addScanFlags(cmd)
	return cmd
}

func runScan(cmd *cobra.Command, args []string) error {
	setupLogging()
	printBanner()

	ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
	defer cancel()

	// Build pipeline components
	discoverer := discovery.NewDiscoverer()
	client := mcpclient.NewClient(commonFlags.SkipSSLVerify)
	inspector := inspect.NewInspector(client, commonFlags.ServerTimeout)
	ruleEngine := rules.NewDefaultEngine()
	analyzer := analysis.NewAnalyzer(commonFlags.AnalysisURL, commonFlags.SkipSSLVerify)
	uploader := upload.NewUploader()

	// Parse control servers
	controlServers := parseControlServers()

	// Create and run pipeline
	p := pipeline.New(pipeline.Config{
		Discoverer:      discoverer,
		Inspector:       inspector,
		RuleEngine:      ruleEngine,
		Analyzer:        analyzer,
		Uploader:        uploader,
		Paths:           args,
		ScanSkills:      commonFlags.Skills,
		ScanAllUsers:    commonFlags.ScanAllUsers,
		ControlServers:  controlServers,
		SkipSSLVerify:   commonFlags.SkipSSLVerify,
		ChecksPerServer: scanFlags.ChecksPerServer,
		Verbose:         commonFlags.Verbose,
	})

	results, err := p.Run(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Format output
	formatter := selectFormatter()
	return formatter.FormatResults(results, output.FormatOptions{
		PrintErrors:    commonFlags.PrintErrors,
		PrintFullDescs: commonFlags.PrintFullDescs,
		InspectMode:    false,
	})
}

func printBanner() {
	if !commonFlags.JSON {
		fmt.Fprintf(os.Stderr, "Agent Scanner v%s\n\n", version.Version)
	}
}

func setupLogging() {
	level := slog.LevelWarn
	if commonFlags.Verbose {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}

func selectFormatter() output.Formatter {
	if commonFlags.JSON {
		return output.NewJSONFormatter(os.Stdout)
	}
	return output.NewTextFormatter(os.Stdout)
}

func parseControlServers() []pipeline.ControlServerConfig {
	var servers []pipeline.ControlServerConfig
	for i, url := range scanFlags.ControlServers {
		cs := pipeline.ControlServerConfig{URL: url}
		if i < len(scanFlags.ControlIdentifier) {
			cs.Identifier = scanFlags.ControlIdentifier[i]
		}
		if i < len(scanFlags.ControlHeaders) {
			cs.Headers = parseHeaders(scanFlags.ControlHeaders[i])
		}
		servers = append(servers, cs)
	}
	return servers
}

// parseHeaders parses a semicolon-separated header string into a map.
// Each header is in "Key: Value" format.
func parseHeaders(raw string) map[string]string {
	headers := make(map[string]string)
	for part := range strings.SplitSeq(raw, ";") {
		part = strings.TrimSpace(part)
		if key, value, ok := strings.Cut(part, ":"); ok {
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if key != "" {
				headers[key] = value
			}
		}
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}
