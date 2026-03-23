package cli

import (
	"fmt"

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
	cmd.Flags().BoolVar(&mcpServerFlags.Tool, "tool", false, "Run in tool-only mode (no background scanning)")
	cmd.Flags().BoolVar(&mcpServerFlags.Background, "background", true, "Enable background periodic scanning")
	cmd.Flags().IntVar(&mcpServerFlags.ScanInterval, "scan-interval", 30, "Background scan interval in minutes")
	cmd.Flags().StringVar(&mcpServerFlags.ClientName, "client-name", "", "Client name for identification")
	return cmd
}

func runMCPServer(_ *cobra.Command, _ []string) error {
	// TODO: Implement MCP server mode in Phase 8
	fmt.Println("MCP server mode not yet implemented")
	return nil
}
