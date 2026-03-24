package cli

import (
	"fmt"

	"github.com/go-authgate/agent-scanner/internal/mcpserver"
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

func runInstall(cmd *cobra.Command, args []string) error {
	var configPath string
	if len(args) > 0 {
		configPath = args[0]
	}

	if configPath == "" {
		defaultPath, err := mcpserver.DefaultConfigPath()
		if err != nil {
			return err
		}
		cmd.Printf("No config file specified, using default: %s\n", defaultPath)
	}

	if err := mcpserver.InstallServer(configPath); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	if configPath == "" {
		configPath = "(default)"
	}
	cmd.Printf("Successfully installed agent-scanner as MCP server in %s\n", configPath)
	return nil
}
