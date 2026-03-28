package cli

import (
	"context"
	"time"

	"github.com/go-authgate/agent-scanner/internal/analysis"
	"github.com/go-authgate/agent-scanner/internal/discovery"
	"github.com/go-authgate/agent-scanner/internal/inspect"
	"github.com/go-authgate/agent-scanner/internal/mcpclient"
	"github.com/go-authgate/agent-scanner/internal/mcpserver"
	"github.com/go-authgate/agent-scanner/internal/models"
	"github.com/go-authgate/agent-scanner/internal/pipeline"
	"github.com/go-authgate/agent-scanner/internal/rules"
	"github.com/spf13/cobra"
)

func newMCPServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp-server",
		Short: "Run agent-scanner as an MCP server",
		Long:  "Starts agent-scanner as an MCP server for continuous background scanning or on-demand tool invocation.",
		RunE:  runMCPServer,
	}
	addCommonFlags(cmd)
	cmd.Flags().
		BoolVar(&mcpServerFlags.Tool, "tool", false, "Run in tool-only mode (no background scanning)")
	cmd.Flags().
		BoolVar(&mcpServerFlags.Background, "background", true, "Enable background periodic scanning")
	cmd.Flags().
		IntVar(&mcpServerFlags.ScanInterval, "scan-interval", 30, "Background scan interval in minutes")
	return cmd
}

func runMCPServer(cmd *cobra.Command, _ []string) error {
	setupLogging()

	// Build pipeline components
	discoverer := discovery.NewDiscoverer()
	client := mcpclient.NewClient(commonFlags.SkipSSLVerify)
	inspector := inspect.NewInspector(client, commonFlags.ServerTimeout)
	ruleEngine := rules.NewDefaultEngine()
	analyzer := analysis.NewAnalyzer(commonFlags.AnalysisURL, commonFlags.SkipSSLVerify)

	// Create the scan function closure
	scanFn := func(ctx context.Context, paths []string, skills bool) ([]models.ScanPathResult, error) {
		p := pipeline.New(pipeline.Config{
			Discoverer:   discoverer,
			Inspector:    inspector,
			RuleEngine:   ruleEngine,
			Analyzer:     analyzer,
			Paths:        paths,
			ScanSkills:   skills,
			ScanAllUsers: commonFlags.ScanAllUsers,
			Verbose:      commonFlags.Verbose,
		})
		return p.Run(ctx)
	}

	background := mcpServerFlags.Background && !mcpServerFlags.Tool

	return mcpserver.RunServer(cmd.Context(), mcpserver.ServerConfig{
		ScanFn:       scanFn,
		Background:   background,
		ScanInterval: time.Duration(mcpServerFlags.ScanInterval) * time.Minute,
	})
}
