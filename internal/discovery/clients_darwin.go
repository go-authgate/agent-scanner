//go:build darwin

package discovery

import "github.com/go-authgate/agent-scanner/internal/models"

// GetWellKnownClients returns well-known AI agent clients for macOS.
func GetWellKnownClients() []models.CandidateClient {
	return []models.CandidateClient{
		{
			Name:             "windsurf",
			ClientExistPaths: []string{"~/Library/Application Support/Windsurf"},
			MCPConfigPaths:   []string{"~/Library/Application Support/Windsurf/User/globalStorage/codeium.windsurf/mcp_config.json"},
		},
		{
			Name:             "cursor",
			ClientExistPaths: []string{"~/Library/Application Support/Cursor"},
			MCPConfigPaths: []string{
				"~/.cursor/mcp.json",
				"~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json",
			},
		},
		{
			Name:             "vscode",
			ClientExistPaths: []string{"~/Library/Application Support/Code"},
			MCPConfigPaths: []string{
				"~/Library/Application Support/Code/User/settings.json",
				"~/.vscode/mcp.json",
			},
		},
		{
			Name:             "claude",
			ClientExistPaths: []string{"~/Library/Application Support/Claude"},
			MCPConfigPaths:   []string{"~/Library/Application Support/Claude/claude_desktop_config.json"},
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
			ClientExistPaths: []string{"~/Library/Application Support/Kiro"},
			MCPConfigPaths:   []string{"~/Library/Application Support/Kiro/User/globalStorage/kiro.kiro/mcp_config.json"},
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
			ClientExistPaths: []string{"~/Library/Application Support/Antigravity"},
			MCPConfigPaths:   []string{"~/Library/Application Support/Antigravity/mcp_config.json"},
		},
		{
			Name:             "openclaw",
			ClientExistPaths: []string{"~/.config/openclaw"},
			MCPConfigPaths:   []string{"~/.config/openclaw/config.json"},
		},
	}
}
