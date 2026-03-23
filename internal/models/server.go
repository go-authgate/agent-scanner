package models

import "encoding/json"

// ServerType represents the transport type of an MCP server.
type ServerType string

const (
	ServerTypeStdio ServerType = "stdio"
	ServerTypeSSE   ServerType = "sse"
	ServerTypeHTTP  ServerType = "http"
	ServerTypeSkill ServerType = "skill"
)

// ServerConfig is a discriminated union interface for all server config types.
type ServerConfig interface {
	GetServerType() ServerType
}

// StdioServer represents an MCP server launched via subprocess.
type StdioServer struct {
	Command          string            `json:"command"`
	Args             []string          `json:"args,omitempty"`
	Env              map[string]string `json:"env,omitempty"`
	BinaryIdentifier string            `json:"binary_identifier,omitempty"`
}

func (s *StdioServer) GetServerType() ServerType { return ServerTypeStdio }

// MarshalJSON implements custom JSON marshaling with type discriminator.
func (s *StdioServer) MarshalJSON() ([]byte, error) {
	type Alias StdioServer
	return json.Marshal(&struct {
		Type ServerType `json:"type"`
		*Alias
	}{
		Type:  ServerTypeStdio,
		Alias: (*Alias)(s),
	})
}

// RemoteServer represents an MCP server reachable over HTTP (SSE or streamable HTTP).
type RemoteServer struct {
	URL     string            `json:"url"`
	Type    ServerType        `json:"type,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

func (s *RemoteServer) GetServerType() ServerType {
	if s.Type != "" {
		return s.Type
	}
	return ServerTypeHTTP
}

// MarshalJSON implements custom JSON marshaling with type discriminator.
func (s *RemoteServer) MarshalJSON() ([]byte, error) {
	type Alias RemoteServer
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(s),
	})
}

// SkillServer represents a local skill directory containing SKILL.md.
type SkillServer struct {
	Path string `json:"path"`
}

func (s *SkillServer) GetServerType() ServerType { return ServerTypeSkill }

// MarshalJSON implements custom JSON marshaling with type discriminator.
func (s *SkillServer) MarshalJSON() ([]byte, error) {
	type Alias SkillServer
	return json.Marshal(&struct {
		Type ServerType `json:"type"`
		*Alias
	}{
		Type:  ServerTypeSkill,
		Alias: (*Alias)(s),
	})
}
