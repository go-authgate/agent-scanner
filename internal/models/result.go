package models

// InitializeResult holds the MCP server's initialization response.
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion,omitempty"`
	ServerInfo      ServerInfo         `json:"serverInfo,omitzero"`
	Capabilities    ServerCapabilities `json:"capabilities,omitzero"`
}

// ServerInfo holds MCP server identification.
type ServerInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// ServerCapabilities describes what the MCP server supports.
type ServerCapabilities struct {
	Tools     *CapabilityInfo `json:"tools,omitempty"`
	Prompts   *CapabilityInfo `json:"prompts,omitempty"`
	Resources *CapabilityInfo `json:"resources,omitempty"`
}

// CapabilityInfo is a marker for a supported capability.
type CapabilityInfo struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ServerSignature holds the full MCP server capabilities snapshot.
type ServerSignature struct {
	Metadata          InitializeResult   `json:"metadata"`
	Prompts           []Prompt           `json:"prompts"`
	Resources         []Resource         `json:"resources"`
	ResourceTemplates []ResourceTemplate `json:"resource_templates"`
	Tools             []Tool             `json:"tools"`
}

// Entities returns all entities from the signature as a flat slice.
func (s *ServerSignature) Entities() []Entity {
	entities := make(
		[]Entity,
		0,
		len(s.Tools)+len(s.Prompts)+len(s.Resources)+len(s.ResourceTemplates),
	)
	for i := range s.Tools {
		entities = append(entities, &s.Tools[i])
	}
	for i := range s.Prompts {
		entities = append(entities, &s.Prompts[i])
	}
	for i := range s.Resources {
		entities = append(entities, &s.Resources[i])
	}
	for i := range s.ResourceTemplates {
		entities = append(entities, &s.ResourceTemplates[i])
	}
	return entities
}

// EntityCount returns the total number of entities.
func (s *ServerSignature) EntityCount() int {
	return len(s.Tools) + len(s.Prompts) + len(s.Resources) + len(s.ResourceTemplates)
}

// ServerScanResult is the result of scanning a single MCP server.
type ServerScanResult struct {
	Name      string           `json:"name,omitempty"`
	Server    ServerConfig     `json:"server"`
	Signature *ServerSignature `json:"signature,omitempty"`
	Error     *ScanError       `json:"error,omitempty"`
}

// IsVerified returns true if the server was successfully inspected.
func (r *ServerScanResult) IsVerified() bool {
	return r.Signature != nil
}

// ScanPathResult aggregates results for one config file or discovery path.
type ScanPathResult struct {
	Client  string               `json:"client,omitempty"`
	Path    string               `json:"path"`
	Servers []ServerScanResult   `json:"servers,omitempty"`
	Issues  []Issue              `json:"issues"`
	Labels  [][]ScalarToolLabels `json:"labels,omitempty"`
	Error   *ScanError           `json:"error,omitempty"`
}

// AllEntities returns all entities across all servers in this scan path.
func (r *ScanPathResult) AllEntities() []Entity {
	var entities []Entity
	for _, server := range r.Servers {
		if server.Signature != nil {
			entities = append(entities, server.Signature.Entities()...)
		}
	}
	return entities
}

// HasIssues returns true if there are any issues with severity >= medium.
func (r *ScanPathResult) HasIssues() bool {
	for _, issue := range r.Issues {
		if SeverityRank(issue.GetSeverity()) >= SeverityRank(SeverityMedium) {
			return true
		}
	}
	return false
}
