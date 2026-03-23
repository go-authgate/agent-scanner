package cli

import (
	"github.com/spf13/cobra"
)

func newInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install-mcp-server [config-file]",
		Short: "Install agent-scanner as an MCP server in client configs",
		Long:  "Adds agent-scanner as a stdio MCP server to the specified client configuration file.",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runInstall,
	}
	return cmd
}

func runInstall(cmd *cobra.Command, _ []string) error {
	// TODO: Implement MCP server installation in Phase 8
	cmd.Println("MCP server installation not yet implemented")
	return nil
}
