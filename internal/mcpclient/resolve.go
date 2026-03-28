package mcpclient

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// resolveCommand tries to find the given command. It first attempts
// exec.LookPath and, if that fails, searches common installation
// directories for the binary.
func resolveCommand(command string) (string, error) {
	// 1. Try the standard PATH lookup first.
	path, err := exec.LookPath(command)
	if err == nil {
		return path, nil
	}

	// 2. Fallback: probe well-known installation directories.
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		home, _ := os.UserHomeDir()
		if found := searchFallbackDirs(command, home); found != "" {
			return found, nil
		}
	}

	// Nothing found — return the original LookPath error.
	return "", fmt.Errorf("command not found: %s: %w", command, err)
}

// searchFallbackDirs probes common installation directories for the
// given command and returns the first match, or "" if none found.
func searchFallbackDirs(command, home string) string {
	// Directories to search (order matters — first match wins).
	// Entries may contain glob wildcards.
	// System dirs are always searched; home-based dirs are only added when home is known.
	var dirs []string
	if home != "" {
		dirs = append(dirs,
			filepath.Join(home, ".nvm", "versions", "node", "*", "bin"), // Node.js via nvm
			filepath.Join(home, ".npm-global", "bin"),                   // npm global
			filepath.Join(home, ".yarn", "bin"),                         // Yarn
			filepath.Join(home, ".pyenv", "shims"),                      // pyenv
			filepath.Join(home, ".cargo", "bin"),                        // Rust/Cargo
		)
	}
	dirs = append(dirs,
		"/opt/homebrew/bin", // Homebrew on ARM Mac
		"/usr/local/bin",    // Homebrew on Intel Mac / system
	)
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".local", "bin")) // pip --user
	}

	for _, dir := range dirs {
		candidate := filepath.Join(dir, command)
		// filepath.Glob handles patterns with wildcards; for plain
		// paths it returns the path only if it exists.
		matches, globErr := filepath.Glob(candidate)
		if globErr != nil {
			continue
		}
		for _, m := range matches {
			if isExecutable(m) {
				return m
			}
		}
	}

	return ""
}

// isExecutable reports whether the path exists and is a regular,
// executable file.
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	// On Unix-like systems check the executable bit.
	return info.Mode()&0o111 != 0
}
