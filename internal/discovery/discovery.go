package discovery

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/go-authgate/agent-scanner/internal/models"
)

// Discoverer finds AI agent clients and their MCP configurations.
type Discoverer interface {
	// DiscoverClients finds all installed AI agent clients on this machine.
	DiscoverClients(ctx context.Context, allUsers bool) []models.CandidateClient
	// ResolveClient resolves a candidate into inspectable clients with parsed configs.
	ResolveClient(ctx context.Context, candidate models.CandidateClient) ([]*models.ClientToInspect, error)
	// ClientFromPath resolves a direct file path into a ClientToInspect.
	ClientFromPath(ctx context.Context, path string, scanSkills bool) ([]*models.ClientToInspect, error)
}

type discoverer struct{}

// NewDiscoverer creates a new Discoverer.
func NewDiscoverer() Discoverer {
	return &discoverer{}
}

func (d *discoverer) DiscoverClients(_ context.Context, allUsers bool) []models.CandidateClient {
	candidates := GetWellKnownClients()
	var found []models.CandidateClient

	homeDirs := getHomeDirs(allUsers)

	for _, candidate := range candidates {
		for _, homeDir := range homeDirs {
			exists := false
			for _, existPath := range candidate.ClientExistPaths {
				expanded := expandPath(existPath, homeDir)
				if _, err := os.Stat(expanded); err == nil {
					exists = true
					break
				}
			}
			if exists {
				found = append(found, candidate)
				break
			}
		}
	}

	slog.Debug("discovered clients", "count", len(found))
	return found
}

func (d *discoverer) ResolveClient(_ context.Context, candidate models.CandidateClient) ([]*models.ClientToInspect, error) {
	var clients []*models.ClientToInspect

	homeDirs := getHomeDirs(false)

	for _, homeDir := range homeDirs {
		client := &models.ClientToInspect{
			Name:       candidate.Name,
			ClientPath: homeDir,
			MCPConfigs: make(map[string]models.MCPConfigOrError),
			SkillsDirs: make(map[string][]models.SkillEntry),
		}

		for _, configPath := range candidate.MCPConfigPaths {
			expanded := expandPath(configPath, homeDir)
			if _, err := os.Stat(expanded); err != nil {
				continue
			}
			cfg, err := ParseMCPConfigFile(expanded)
			if err != nil {
				client.MCPConfigs[expanded] = models.MCPConfigOrError{
					Error: models.NewScanError(err.Error(), models.ErrCatParseError, false),
				}
				continue
			}
			client.MCPConfigs[expanded] = models.MCPConfigOrError{Config: cfg}
		}

		for _, skillsPath := range candidate.SkillsDirPaths {
			expanded := expandPath(skillsPath, homeDir)
			if info, err := os.Stat(expanded); err == nil && info.IsDir() {
				entries := discoverSkills(expanded)
				if len(entries) > 0 {
					client.SkillsDirs[expanded] = entries
				}
			}
		}

		if len(client.MCPConfigs) > 0 || len(client.SkillsDirs) > 0 {
			clients = append(clients, client)
		}
	}

	return clients, nil
}

func (d *discoverer) ClientFromPath(_ context.Context, path string, scanSkills bool) ([]*models.ClientToInspect, error) {
	// Check if it's a direct scan URI
	if IsDirectScan(path) {
		name, serverCfg := DirectScanToServerConfig(path)
		if serverCfg == nil {
			return nil, nil
		}
		client := &models.ClientToInspect{
			Name:       name,
			ClientPath: path,
			MCPConfigs: map[string]models.MCPConfigOrError{
				path: {Config: &singleServerConfig{name: name, server: serverCfg}},
			},
		}
		return []*models.ClientToInspect{client}, nil
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	// Check if path is a skill directory (contains SKILL.md)
	if isSkillDirectory(absPath) {
		skillName := filepath.Base(absPath)
		client := &models.ClientToInspect{
			Name:       skillName,
			ClientPath: absPath,
			MCPConfigs: make(map[string]models.MCPConfigOrError),
			SkillsDirs: map[string][]models.SkillEntry{
				absPath: {{Name: skillName, Server: &models.SkillServer{Path: absPath}}},
			},
		}
		return []*models.ClientToInspect{client}, nil
	}

	// Check if path is a directory containing skill subdirectories
	if info, statErr := os.Stat(absPath); statErr == nil && info.IsDir() {
		entries := discoverSkills(absPath)
		if len(entries) > 0 {
			client := &models.ClientToInspect{
				Name:       filepath.Base(absPath),
				ClientPath: absPath,
				MCPConfigs: make(map[string]models.MCPConfigOrError),
				SkillsDirs: map[string][]models.SkillEntry{absPath: entries},
			}
			return []*models.ClientToInspect{client}, nil
		}
	}

	// Try to parse as config file
	cfg, err := ParseMCPConfigFile(absPath)
	if err != nil {
		return nil, err
	}

	clientName := getClientFromPath(absPath)
	client := &models.ClientToInspect{
		Name:       clientName,
		ClientPath: filepath.Dir(absPath),
		MCPConfigs: map[string]models.MCPConfigOrError{
			absPath: {Config: cfg},
		},
	}

	if scanSkills {
		// Look for skills in sibling directories
		dir := filepath.Dir(absPath)
		entries := discoverSkills(dir)
		if len(entries) > 0 {
			client.SkillsDirs = map[string][]models.SkillEntry{dir: entries}
		}
	}

	return []*models.ClientToInspect{client}, nil
}

// isSkillDirectory returns true if the path is a directory containing SKILL.md.
func isSkillDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	for _, name := range []string{"SKILL.md", "skill.md"} {
		if _, err := os.Stat(filepath.Join(path, name)); err == nil {
			return true
		}
	}
	return false
}

// discoverSkills finds skill directories under a given path.
func discoverSkills(dir string) []models.SkillEntry {
	var entries []models.SkillEntry

	items, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	for _, item := range items {
		if !item.IsDir() {
			continue
		}
		skillPath := filepath.Join(dir, item.Name())
		// Check for SKILL.md or skill.md
		for _, name := range []string{"SKILL.md", "skill.md"} {
			if _, err := os.Stat(filepath.Join(skillPath, name)); err == nil {
				entries = append(entries, models.SkillEntry{
					Name:   item.Name(),
					Server: &models.SkillServer{Path: skillPath},
				})
				break
			}
		}
	}

	return entries
}

// getClientFromPath tries to identify the client type from a config file path.
func getClientFromPath(path string) string {
	dir := filepath.Base(filepath.Dir(path))
	filename := filepath.Base(path)

	switch {
	case filename == "claude_desktop_config.json":
		return "claude"
	case dir == ".claude" || filename == ".claude.json":
		return "claude code"
	case dir == "Cursor" || dir == ".cursor":
		return "cursor"
	case dir == "Code" || dir == ".vscode":
		return "vscode"
	case dir == "Windsurf":
		return "windsurf"
	default:
		return filepath.Base(path)
	}
}

// singleServerConfig wraps a single server for direct scan use.
type singleServerConfig struct {
	name   string
	server models.ServerConfig
}

func (s *singleServerConfig) ConfigType() string { return "direct" }
func (s *singleServerConfig) GetServers() map[string]models.ServerConfig {
	return map[string]models.ServerConfig{s.name: s.server}
}

// getHomeDirs returns home directories to scan.
func getHomeDirs(allUsers bool) []string {
	if allUsers {
		return getReadableHomeDirs()
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{home}
}

// expandPath replaces ~ with the given home directory.
func expandPath(path string, homeDir string) string {
	if len(path) > 0 && path[0] == '~' {
		return filepath.Join(homeDir, path[1:])
	}
	return path
}
