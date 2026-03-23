package output

import (
	"encoding/json"
	"io"

	"github.com/go-authgate/agent-scanner/internal/models"
)

type jsonFormatter struct {
	writer io.Writer
}

// NewJSONFormatter creates a JSON output formatter.
func NewJSONFormatter(w io.Writer) Formatter {
	return &jsonFormatter{writer: w}
}

func (f *jsonFormatter) FormatResults(results []models.ScanPathResult, _ FormatOptions) error {
	enc := json.NewEncoder(f.writer)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}
