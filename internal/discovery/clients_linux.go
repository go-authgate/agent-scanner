//go:build linux

package discovery

import "github.com/go-authgate/agent-scanner/internal/models"

// GetWellKnownClients returns well-known AI agent clients for Linux.
func GetWellKnownClients() []models.CandidateClient {
	return []models.CandidateClient{
		{
			Name:             "windsurf",
			ClientExistPaths: []string{"~/.config/Windsurf"},
			MCPConfigPaths:   []string{"~/.config/Windsurf/User/globalStorage/codeium.windsurf/mcp_config.json"},
		},
		{
			Name:             "cursor",
			ClientExistPaths: []string{"~/.config/Cursor"},
			MCPConfigPaths: []string{
				"~/.cursor/mcp.json",
				"~/.config/Cursor/User/globalStorage/cursor.mcp/mcp.json",
			},
		},
		{
			Name:             "vscode",
			ClientExistPaths: []string{"~/.config/Code"},
			MCPConfigPaths: []string{
				"~/.config/Code/User/settings.json",
				"~/.vscode/mcp.json",
			},
		},
		{
			Name:             "claude code",
			ClientExistPaths: []string{"~/.claude"},
			MCPConfigPaths:   []string{"~/.claude.json"},
			SkillsDirPaths:   []string{"~/.claude/commands"},
		},
		{
			Name:             "gemini cli",
			ClientExistPaths: []string{"~/.gemini"},
			MCPConfigPaths:   []string{"~/.gemini/settings.json"},
		},
		{
			Name:             "kiro",
			ClientExistPaths: []string{"~/.config/Kiro"},
			MCPConfigPaths:   []string{"~/.config/Kiro/User/globalStorage/kiro.kiro/mcp_config.json"},
		},
		{
			Name:             "opencode",
			ClientExistPaths: []string{"~/.config/opencode"},
			MCPConfigPaths:   []string{"~/.config/opencode/config.json"},
		},
		{
			Name:             "codex",
			ClientExistPaths: []string{"~/.codex"},
			MCPConfigPaths:   []string{"~/.codex/config.json"},
		},
		{
			Name:             "antigravity",
			ClientExistPaths: []string{"~/.config/Antigravity"},
			MCPConfigPaths:   []string{"~/.config/Antigravity/mcp_config.json"},
		},
		{
			Name:             "openclaw",
			ClientExistPaths: []string{"~/.config/openclaw"},
			MCPConfigPaths:   []string{"~/.config/openclaw/config.json"},
		},
	}
}
