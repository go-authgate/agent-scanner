package mcpserver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// DefaultConfigPath returns the default Claude Desktop config path for the current platform.
func DefaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine home directory: %w", err)
	}

	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(
			home,
			"Library",
			"Application Support",
			"Claude",
			"claude_desktop_config.json",
		), nil
	case "windows":
		return filepath.Join(
			home,
			"AppData",
			"Roaming",
			"Claude",
			"claude_desktop_config.json",
		), nil
	case "linux":
		return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"), nil
	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// mcpServerEntry represents an MCP server entry in a config file.
type mcpServerEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// InstallServer adds agent-scanner as an MCP server in the specified config file.
// If configPath is empty, it defaults to the Claude Desktop config path.
func InstallServer(configPath string) error {
	if configPath == "" {
		defaultPath, err := DefaultConfigPath()
		if err != nil {
			return err
		}
		configPath = defaultPath
	}

	// Expand ~ in path
	if strings.HasPrefix(configPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("unable to expand home directory: %w", err)
		}
		configPath = filepath.Join(home, configPath[2:])
	}

	// Find the agent-scanner binary path
	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("unable to determine binary path: %w", err)
	}
	binaryPath, err = filepath.EvalSymlinks(binaryPath)
	if err != nil {
		return fmt.Errorf("unable to resolve binary path: %w", err)
	}

	// Read existing config or start with empty object
	var config map[string]any

	data, err := os.ReadFile(configPath)
	switch {
	case err != nil:
		if !os.IsNotExist(err) {
			return fmt.Errorf("reading config file: %w", err)
		}
		config = make(map[string]any)
	case strings.TrimSpace(string(data)) == "":
		config = make(map[string]any)
	default:
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("parsing config file: %w", err)
		}
	}

	// Get or create mcpServers section
	var mcpServers map[string]any
	if existing, exists := config["mcpServers"]; !exists {
		mcpServers = make(map[string]any)
	} else {
		var ok bool
		mcpServers, ok = existing.(map[string]any)
		if !ok {
			return fmt.Errorf(
				"config key %q has unexpected type %T; expected object",
				"mcpServers",
				existing,
			)
		}
	}

	// Add/update agent-scanner entry
	mcpServers["agent-scanner"] = mcpServerEntry{
		Command: binaryPath,
		Args:    []string{"mcp-server"},
	}
	config["mcpServers"] = mcpServers

	// Marshal with indentation
	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	// Ensure parent directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	// Write config file
	if err := os.WriteFile(configPath, append(output, '\n'), 0o644); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}

	return nil
}
