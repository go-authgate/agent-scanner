package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-authgate/agent-scanner/internal/discovery"
	"github.com/go-authgate/agent-scanner/internal/inspect"
	"github.com/go-authgate/agent-scanner/internal/mcpclient"
	"github.com/go-authgate/agent-scanner/internal/output"
	"github.com/go-authgate/agent-scanner/internal/pipeline"
	"github.com/go-authgate/agent-scanner/internal/version"
	"github.com/spf13/cobra"
)

func newInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect [paths...]",
		Short: "Inspect MCP servers and list their tools/prompts/resources",
		Long:  "Inspect connects to MCP servers and lists their capabilities without performing security analysis.",
		RunE:  runInspect,
	}
	addCommonFlags(cmd)
	return cmd
}

func runInspect(cmd *cobra.Command, args []string) error {
	setupLogging()

	if !commonFlags.JSON {
		fmt.Fprintf(os.Stderr, "Agent Scanner v%s (inspect mode)\n\n", version.Version)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
	defer cancel()

	discoverer := discovery.NewDiscoverer()
	client := mcpclient.NewClient()
	inspector := inspect.NewInspector(client, commonFlags.ServerTimeout)

	p := pipeline.New(pipeline.Config{
		Discoverer:   discoverer,
		Inspector:    inspector,
		Paths:        args,
		ScanSkills:   commonFlags.Skills,
		ScanAllUsers: commonFlags.ScanAllUsers,
		InspectOnly:  true,
		Verbose:      commonFlags.Verbose,
	})

	results, err := p.Run(ctx)
	if err != nil {
		return fmt.Errorf("inspect failed: %w", err)
	}

	formatter := selectFormatter()
	return formatter.FormatResults(results, output.FormatOptions{
		PrintErrors:    commonFlags.PrintErrors,
		PrintFullDescs: commonFlags.PrintFullDescs,
		InspectMode:    true,
	})
}
