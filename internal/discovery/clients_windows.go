//go:build windows

package discovery

import "github.com/go-authgate/agent-scanner/internal/models"

// GetWellKnownClients returns well-known AI agent clients for Windows.
func GetWellKnownClients() []models.CandidateClient {
	return []models.CandidateClient{
		{
			Name:             "windsurf",
			ClientExistPaths: []string{"~/AppData/Roaming/Windsurf"},
			MCPConfigPaths:   []string{"~/AppData/Roaming/Windsurf/User/globalStorage/codeium.windsurf/mcp_config.json"},
		},
		{
			Name:             "cursor",
			ClientExistPaths: []string{"~/AppData/Roaming/Cursor"},
			MCPConfigPaths: []string{
				"~/.cursor/mcp.json",
				"~/AppData/Roaming/Cursor/User/globalStorage/cursor.mcp/mcp.json",
			},
		},
		{
			Name:             "vscode",
			ClientExistPaths: []string{"~/AppData/Roaming/Code"},
			MCPConfigPaths: []string{
				"~/AppData/Roaming/Code/User/settings.json",
				"~/.vscode/mcp.json",
			},
		},
		{
			Name:             "claude",
			ClientExistPaths: []string{"~/AppData/Roaming/Claude"},
			MCPConfigPaths:   []string{"~/AppData/Roaming/Claude/claude_desktop_config.json"},
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
			ClientExistPaths: []string{"~/AppData/Roaming/Kiro"},
			MCPConfigPaths:   []string{"~/AppData/Roaming/Kiro/User/globalStorage/kiro.kiro/mcp_config.json"},
		},
		{
			Name:             "codex",
			ClientExistPaths: []string{"~/.codex"},
			MCPConfigPaths:   []string{"~/.codex/config.json"},
		},
		{
			Name:             "openclaw",
			ClientExistPaths: []string{"~/.config/openclaw"},
			MCPConfigPaths:   []string{"~/.config/openclaw/config.json"},
		},
	}
}
