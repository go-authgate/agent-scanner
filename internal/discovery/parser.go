package discovery

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/go-authgate/agent-scanner/internal/models"
	"github.com/tidwall/jsonc"
)

// ParseMCPConfigFile reads and parses an MCP configuration file.
// Supports JSON and JSONC (JSON with comments) formats.
func ParseMCPConfigFile(path string) (models.MCPConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Strip comments (JSONC → JSON)
	data = jsonc.ToJSON(data)

	// Try each config format in order
	parsers := []struct {
		name  string
		parse func([]byte) (models.MCPConfig, error)
	}{
		{"claude_code", parseClaudeCodeConfig},
		{"claude", parseClaudeConfig},
		{"vscode", parseVSCodeConfig},
		{"vscode_mcp", parseVSCodeMCPConfig},
	}

	for _, p := range parsers {
		cfg, err := p.parse(data)
		if err == nil && cfg != nil {
			servers := cfg.GetServers()
			if len(servers) > 0 {
				return cfg, nil
			}
		}
	}

	return &models.UnknownMCPConfig{}, nil
}

func parseClaudeConfig(data []byte) (models.MCPConfig, error) {
	var cfg models.ClaudeConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if len(cfg.MCPServers) == 0 {
		return nil, fmt.Errorf("no mcpServers found")
	}
	return &cfg, nil
}

func parseClaudeCodeConfig(data []byte) (models.MCPConfig, error) {
	var cfg models.ClaudeCodeConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	// Claude Code config is distinguished by having "projects" key.
	// Without it, fall through to plain Claude config.
	if len(cfg.Projects) == 0 {
		return nil, fmt.Errorf("no projects found (not a claude code config)")
	}
	return &cfg, nil
}

func parseVSCodeConfig(data []byte) (models.MCPConfig, error) {
	var cfg models.VSCodeConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if len(cfg.MCP.Servers) == 0 {
		return nil, fmt.Errorf("no mcp.servers found")
	}
	return &cfg, nil
}

func parseVSCodeMCPConfig(data []byte) (models.MCPConfig, error) {
	var cfg models.VSCodeMCPConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if len(cfg.Servers) == 0 {
		return nil, fmt.Errorf("no servers found")
	}
	return &cfg, nil
}
