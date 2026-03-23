package models

import "encoding/json"

// EntityKind distinguishes MCP entity types.
type EntityKind string

const (
	EntityKindTool             EntityKind = "tool"
	EntityKindPrompt           EntityKind = "prompt"
	EntityKindResource         EntityKind = "resource"
	EntityKindResourceTemplate EntityKind = "resource_template"
)

// Entity is the interface for all MCP entities (tools, prompts, resources).
type Entity interface {
	GetName() string
	GetDescription() string
	Kind() EntityKind
}

// Tool represents an MCP tool.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

func (t *Tool) GetName() string        { return t.Name }
func (t *Tool) GetDescription() string { return t.Description }
func (t *Tool) Kind() EntityKind       { return EntityKindTool }

// Prompt represents an MCP prompt.
type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// PromptArgument represents an argument for a prompt.
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

func (p *Prompt) GetName() string        { return p.Name }
func (p *Prompt) GetDescription() string { return p.Description }
func (p *Prompt) Kind() EntityKind       { return EntityKindPrompt }

// Resource represents an MCP resource.
type Resource struct {
	Name        string `json:"name"`
	URI         string `json:"uri"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

func (r *Resource) GetName() string        { return r.Name }
func (r *Resource) GetDescription() string { return r.Description }
func (r *Resource) Kind() EntityKind       { return EntityKindResource }

// ResourceTemplate represents an MCP resource template.
type ResourceTemplate struct {
	Name        string `json:"name"`
	URITemplate string `json:"uriTemplate"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

func (rt *ResourceTemplate) GetName() string        { return rt.Name }
func (rt *ResourceTemplate) GetDescription() string { return rt.Description }
func (rt *ResourceTemplate) Kind() EntityKind       { return EntityKindResourceTemplate }

// EntityToTool converts any Entity to a Tool representation for uniform analysis.
func EntityToTool(e Entity) Tool {
	t := Tool{
		Name:        e.GetName(),
		Description: e.GetDescription(),
	}
	return t
}
