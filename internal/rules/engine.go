package rules

import "github.com/go-authgate/agent-scanner/internal/models"

// Engine runs all registered rules against scan results.
type Engine interface {
	Register(rule Rule)
	Run(ctx *RuleContext) []models.Issue
}

type engine struct {
	rules []Rule
}

// NewEngine creates an empty rule engine.
func NewEngine() Engine {
	return &engine{}
}

// NewDefaultEngine creates an engine with all built-in rules registered.
func NewDefaultEngine() Engine {
	e := &engine{}
	for _, r := range DefaultRules() {
		e.Register(r)
	}
	return e
}

func (e *engine) Register(rule Rule) {
	e.rules = append(e.rules, rule)
}

func (e *engine) Run(ctx *RuleContext) []models.Issue {
	var allIssues []models.Issue
	for _, rule := range e.rules {
		issues := rule.Check(ctx)
		allIssues = append(allIssues, issues...)
	}
	return allIssues
}
