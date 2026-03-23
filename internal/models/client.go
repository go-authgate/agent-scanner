package models

// CandidateClient represents a well-known AI agent client installation.
type CandidateClient struct {
	Name             string   `json:"name"`
	ClientExistPaths []string `json:"client_exists_paths"`
	MCPConfigPaths   []string `json:"mcp_config_paths"`
	SkillsDirPaths   []string `json:"skills_dir_paths,omitempty"`
}

// ClientToInspect represents a client with resolved config paths ready for inspection.
type ClientToInspect struct {
	Name       string                        `json:"name"`
	ClientPath string                        `json:"client_path"`
	MCPConfigs map[string]MCPConfigOrError   `json:"mcp_configs"`
	SkillsDirs map[string][]SkillEntry       `json:"skills_dirs,omitempty"`
}

// MCPConfigOrError holds either a parsed config or an error.
type MCPConfigOrError struct {
	Config MCPConfig  `json:"config,omitempty"`
	Error  *ScanError `json:"error,omitempty"`
}

// SkillEntry represents a discovered skill.
type SkillEntry struct {
	Name   string      `json:"name"`
	Server *SkillServer `json:"server"`
}

// InspectedExtension holds the result of inspecting a single server/skill.
type InspectedExtension struct {
	Name      string           `json:"name"`
	Config    ServerConfig     `json:"config"`
	Signature *ServerSignature `json:"signature,omitempty"`
	Error     *ScanError       `json:"error,omitempty"`
}

// InspectedClient represents a fully inspected AI agent client.
type InspectedClient struct {
	Name       string                              `json:"name"`
	ClientPath string                              `json:"client_path"`
	Extensions map[string][]InspectedExtension     `json:"extensions"`
}
