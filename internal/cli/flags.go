package cli

import "github.com/spf13/cobra"

// CommonFlags holds flags shared across scan/inspect commands.
type CommonFlags struct {
	StorageFile      string
	AnalysisURL      string
	VerificationH    []string
	Verbose          bool
	PrintErrors      bool
	PrintFullDescs   bool
	JSON             bool
	SkipSSLVerify    bool
	Skills           bool
	ScanAllUsers     bool
	ServerTimeout    int
	SuppressServerIO bool
}

// ScanFlags holds scan-specific flags.
type ScanFlags struct {
	ChecksPerServer   int
	ControlServers    []string
	ControlHeaders    []string
	ControlIdentifier []string
}

// MCPServerFlags holds mcp-server subcommand flags.
type MCPServerFlags struct {
	Tool         bool
	Background   bool
	ScanInterval int
}

var (
	commonFlags    CommonFlags
	scanFlags      ScanFlags
	mcpServerFlags MCPServerFlags
)

// addCommonFlags registers flags shared across scan/inspect commands.
func addCommonFlags(cmd *cobra.Command) {
	cmd.Flags().
		StringVar(&commonFlags.StorageFile, "storage-file", "~/.agent-scanner", "Path to storage file")
	cmd.Flags().StringVar(&commonFlags.AnalysisURL, "analysis-url", "", "Verification server URL")
	cmd.Flags().
		StringSliceVar(&commonFlags.VerificationH, "verification-H", nil, "Additional headers for verification API")
	cmd.Flags().BoolVar(&commonFlags.Verbose, "verbose", false, "Enable verbose logging")
	cmd.Flags().
		BoolVar(&commonFlags.PrintErrors, "print-errors", false, "Print server startup errors/tracebacks")
	cmd.Flags().
		BoolVar(&commonFlags.PrintFullDescs, "print-full-descriptions", false, "Print full entity descriptions")
	cmd.Flags().BoolVar(&commonFlags.JSON, "json", false, "Output results as JSON")
	cmd.Flags().
		BoolVar(&commonFlags.SkipSSLVerify, "skip-ssl-verify", false, "Disable SSL certificate verification")
	cmd.Flags().BoolVar(&commonFlags.Skills, "skills", false, "Include skill scanning")
	cmd.Flags().
		BoolVar(&commonFlags.ScanAllUsers, "scan-all-users", false, "Scan all user home directories")
	cmd.Flags().
		IntVar(&commonFlags.ServerTimeout, "server-timeout", 10, "MCP server connection timeout in seconds")
	cmd.Flags().
		BoolVar(&commonFlags.SuppressServerIO, "suppress-mcpserver-io", true, "Suppress MCP server stdout/stderr")
}

// addScanFlags registers scan-specific flags.
func addScanFlags(cmd *cobra.Command) {
	cmd.Flags().
		IntVar(&scanFlags.ChecksPerServer, "checks-per-server", 1, "Number of verification checks per server")
	cmd.Flags().
		StringSliceVar(&scanFlags.ControlServers, "control-server", nil, "Control server URLs for result upload")
	cmd.Flags().
		StringSliceVar(&scanFlags.ControlHeaders, "control-server-H", nil, "Additional headers for control servers")
	cmd.Flags().
		StringSliceVar(&scanFlags.ControlIdentifier, "control-identifier", nil, "Identifiers for control servers")
}
