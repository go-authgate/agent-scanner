package httperrors

import (
	"fmt"
	"strings"
	"unicode"
)

// ClientError is a non-retryable HTTP error (4xx).
type ClientError struct {
	StatusCode int
	Body       string
}

func (e *ClientError) Error() string {
	return fmt.Sprintf("status %d: %s", e.StatusCode, e.Body)
}

// NonRetryableError wraps errors that should not be retried
// (e.g., request construction failures, JSON decode errors).
type NonRetryableError struct {
	Err error
}

func (e *NonRetryableError) Error() string { return e.Err.Error() }
func (e *NonRetryableError) Unwrap() error { return e.Err }

// SanitizeBodySnippet truncates s to approximately maxLen bytes (the
// returned string may be slightly longer due to a " [truncated]" suffix)
// and replaces all Unicode control characters with spaces for safe single-line logging.
func SanitizeBodySnippet(s string, maxLen int) string {
	if len(s) > maxLen {
		s = s[:maxLen] + " [truncated]"
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}
