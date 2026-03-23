package output

import "github.com/go-authgate/agent-scanner/internal/models"

// FormatOptions controls output behavior.
type FormatOptions struct {
	PrintErrors    bool
	PrintFullDescs bool
	InspectMode    bool
}

// Formatter controls how scan results are presented to the user.
type Formatter interface {
	FormatResults(results []models.ScanPathResult, opts FormatOptions) error
}
