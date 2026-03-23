package models

// ErrorCategory classifies scan errors.
type ErrorCategory string

const (
	ErrCatFileNotFound  ErrorCategory = "file_not_found"
	ErrCatUnknownConfig ErrorCategory = "unknown_config"
	ErrCatParseError    ErrorCategory = "parse_error"
	ErrCatServerStartup ErrorCategory = "server_startup"
	ErrCatServerHTTP    ErrorCategory = "server_http_error"
	ErrCatAnalysisError ErrorCategory = "analysis_error"
	ErrCatSkillScan     ErrorCategory = "skill_scan_error"
)

// ScanError is a structured error from the scan pipeline.
type ScanError struct {
	Message      string        `json:"message,omitempty"`
	Exception    string        `json:"exception,omitempty"`
	Traceback    string        `json:"traceback,omitempty"`
	IsFailure    bool          `json:"is_failure"`
	Category     ErrorCategory `json:"category,omitempty"`
	ServerOutput string        `json:"server_output,omitempty"`
}

// Error implements the error interface.
func (e *ScanError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return string(e.Category)
}

// NewScanError creates a ScanError with a message and category.
func NewScanError(msg string, category ErrorCategory, isFailure bool) *ScanError {
	return &ScanError{
		Message:   msg,
		Category:  category,
		IsFailure: isFailure,
	}
}

// ErrorToIssueCode maps error categories to issue codes.
func ErrorToIssueCode(category ErrorCategory) string {
	switch category {
	case ErrCatServerStartup:
		return CodeServerStartup
	case ErrCatSkillScan:
		return CodeSkillScanError
	case ErrCatFileNotFound:
		return CodeFileNotFound
	case ErrCatUnknownConfig:
		return CodeUnknownConfig
	case ErrCatParseError:
		return CodeParseError
	case ErrCatServerHTTP:
		return CodeServerHTTPError
	case ErrCatAnalysisError:
		return CodeAnalysisError
	default:
		return CodeUnknownError
	}
}
