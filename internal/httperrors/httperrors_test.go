package httperrors

import (
	"errors"
	"strings"
	"testing"
)

func TestClientError_Error(t *testing.T) {
	err := &ClientError{StatusCode: 403, Body: "forbidden"}
	got := err.Error()
	if got != "status 403: forbidden" {
		t.Errorf("got %q, want %q", got, "status 403: forbidden")
	}
}

func TestNonRetryableError_Unwrap(t *testing.T) {
	inner := errors.New("bad request")
	err := &NonRetryableError{Err: inner}

	if err.Error() != "bad request" {
		t.Errorf("Error() = %q, want %q", err.Error(), "bad request")
	}
	if !errors.Is(err, inner) {
		t.Error("expected errors.Is to find inner error")
	}
}

func TestSanitizeBodySnippet(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		checks func(t *testing.T, result string)
	}{
		{
			name:   "short string unchanged",
			input:  "hello world",
			maxLen: 100,
			checks: func(t *testing.T, result string) {
				if result != "hello world" {
					t.Errorf("got %q", result)
				}
			},
		},
		{
			name:   "truncated",
			input:  "abcdefghij",
			maxLen: 5,
			checks: func(t *testing.T, result string) {
				if !strings.HasPrefix(result, "abcde") {
					t.Errorf("got %q, want prefix 'abcde'", result)
				}
				if !strings.Contains(result, "[truncated]") {
					t.Error("expected [truncated] suffix")
				}
			},
		},
		{
			name:   "control chars replaced",
			input:  "line1\nline2\ttab\x00null",
			maxLen: 100,
			checks: func(t *testing.T, result string) {
				if strings.ContainsAny(result, "\n\t\x00") {
					t.Errorf("control characters not replaced: %q", result)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeBodySnippet(tt.input, tt.maxLen)
			tt.checks(t, result)
		})
	}
}
