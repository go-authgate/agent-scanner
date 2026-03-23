package rules

import "github.com/go-authgate/agent-scanner/internal/models"

// Rule is a single security check.
type Rule interface {
	// Code returns the issue code (e.g., "E001", "W001").
	Code() string
	// Name returns a human-readable name.
	Name() string
	// Check runs the rule against the given context and returns any issues found.
	Check(ctx *RuleContext) []models.Issue
}

// RuleContext provides data to rules for evaluation.
type RuleContext struct {
	Servers []models.ServerScanResult
	// Labels from remote analysis (may be nil if not analyzed).
	Labels [][]models.ScalarToolLabels
}

// IndexedEntity associates an entity with its server and entity indices.
type IndexedEntity struct {
	ServerIndex int
	EntityIndex int
	Entity      models.Entity
	ServerName  string
}

// AllEntities returns a flat list of all entities with their indices.
func (rc *RuleContext) AllEntities() []IndexedEntity {
	var entities []IndexedEntity
	for si, server := range rc.Servers {
		if server.Signature == nil {
			continue
		}
		for ei, entity := range server.Signature.Entities() {
			entities = append(entities, IndexedEntity{
				ServerIndex: si,
				EntityIndex: ei,
				Entity:      entity,
				ServerName:  server.Name,
			})
		}
	}
	return entities
}
