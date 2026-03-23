//go:build !darwin

package signed

import "github.com/go-authgate/agent-scanner/internal/models"

// CheckBinarySignature is a no-op on non-macOS platforms.
func CheckBinarySignature(_ *models.StdioServer) {}
