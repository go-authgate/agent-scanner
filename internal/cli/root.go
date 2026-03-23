package cli

import (
	"fmt"

	"github.com/go-authgate/agent-scanner/internal/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "agent-scanner",
	Short: "Security scanner for AI agents, MCP servers, and agent skills",
	Long: `Agent Scanner discovers installed AI agent clients (Claude, Cursor, VS Code, Windsurf, etc.),
connects to their configured MCP servers, and detects prompt injections, tool poisoning,
toxic flows, and other security threats.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("Agent Scanner v%s\n", version.Version)
		fmt.Printf("  Git Commit: %s\n", version.GitCommit)
		fmt.Printf("  Build Time: %s\n", version.BuildTime)
		fmt.Printf("  Go Version: %s\n", version.GoVersion)
		fmt.Printf("  OS/Arch:    %s/%s\n", version.BuildOS, version.BuildArch)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newInspectCmd())
	rootCmd.AddCommand(newMCPServerCmd())
	rootCmd.AddCommand(newInstallCmd())
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
