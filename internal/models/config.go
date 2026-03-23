package models

// MCPConfig is the interface for all MCP configuration file formats.
type MCPConfig interface {
	// GetServers returns all server configurations keyed by name.
	GetServers() map[string]ServerConfig
	// ConfigType returns a string identifying the config format.
	ConfigType() string
}

// ClaudeConfigFile represents claude_desktop_config.json format.
// Structure: { "mcpServers": { "name": { "command": "...", "args": [...] } } }
type ClaudeConfigFile struct {
	MCPServers map[string]ServerConfigJSON `json:"mcpServers"`
}

func (c *ClaudeConfigFile) ConfigType() string { return "claude" }

func (c *ClaudeConfigFile) GetServers() map[string]ServerConfig {
	servers := make(map[string]ServerConfig, len(c.MCPServers))
	for name, raw := range c.MCPServers {
		servers[name] = raw.ToServerConfig()
	}
	return servers
}

// ClaudeCodeConfigFile represents .claude.json format with nested projects.
// Structure: { "projects": { "/path": { "mcpServers": { ... } } } }
type ClaudeCodeConfigFile struct {
	MCPServers map[string]ServerConfigJSON            `json:"mcpServers,omitempty"`
	Projects   map[string]ClaudeCodeProjectConfig     `json:"projects,omitempty"`
}

// ClaudeCodeProjectConfig is a nested project within ClaudeCodeConfigFile.
type ClaudeCodeProjectConfig struct {
	MCPServers map[string]ServerConfigJSON `json:"mcpServers,omitempty"`
}

func (c *ClaudeCodeConfigFile) ConfigType() string { return "claude_code" }

func (c *ClaudeCodeConfigFile) GetServers() map[string]ServerConfig {
	servers := make(map[string]ServerConfig)
	// Top-level servers
	for name, raw := range c.MCPServers {
		servers[name] = raw.ToServerConfig()
	}
	// Project-level servers
	for _, project := range c.Projects {
		for name, raw := range project.MCPServers {
			servers[name] = raw.ToServerConfig()
		}
	}
	return servers
}

// VSCodeConfigFile represents VS Code settings.json format.
// Structure: { "mcp": { "servers": { ... } } }
type VSCodeConfigFile struct {
	MCP VSCodeMCPSection `json:"mcp"`
}

// VSCodeMCPSection holds the "mcp" section of VS Code settings.
type VSCodeMCPSection struct {
	Inputs  map[string]any                 `json:"inputs,omitempty"`
	Servers map[string]ServerConfigJSON    `json:"servers"`
}

func (c *VSCodeConfigFile) ConfigType() string { return "vscode" }

func (c *VSCodeConfigFile) GetServers() map[string]ServerConfig {
	servers := make(map[string]ServerConfig, len(c.MCP.Servers))
	for name, raw := range c.MCP.Servers {
		servers[name] = raw.ToServerConfig()
	}
	return servers
}

// VSCodeMCPConfigFile represents .vscode/mcp.json or mcp.json format.
// Structure: { "servers": { ... } }
type VSCodeMCPConfigFile struct {
	Inputs  map[string]any              `json:"inputs,omitempty"`
	Servers map[string]ServerConfigJSON `json:"servers"`
}

func (c *VSCodeMCPConfigFile) ConfigType() string { return "vscode_mcp" }

func (c *VSCodeMCPConfigFile) GetServers() map[string]ServerConfig {
	servers := make(map[string]ServerConfig, len(c.Servers))
	for name, raw := range c.Servers {
		servers[name] = raw.ToServerConfig()
	}
	return servers
}

// UnknownMCPConfig is a placeholder for unrecognized config formats.
type UnknownMCPConfig struct{}

func (c *UnknownMCPConfig) ConfigType() string                  { return "unknown" }
func (c *UnknownMCPConfig) GetServers() map[string]ServerConfig { return nil }

// ServerConfigJSON is the raw JSON representation that gets parsed into a typed ServerConfig.
type ServerConfigJSON struct {
	// Common
	Type string `json:"type,omitempty"`

	// StdioServer fields
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`

	// RemoteServer fields
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// ToServerConfig converts the raw JSON to a typed ServerConfig.
func (s *ServerConfigJSON) ToServerConfig() ServerConfig {
	// If URL is present, it's a remote server
	if s.URL != "" {
		st := ServerType(s.Type)
		if st == "" {
			st = ServerTypeHTTP
		}
		return &RemoteServer{
			URL:     s.URL,
			Type:    st,
			Headers: s.Headers,
		}
	}
	// Otherwise it's a stdio server
	return &StdioServer{
		Command: s.Command,
		Args:    s.Args,
		Env:     s.Env,
	}
}
