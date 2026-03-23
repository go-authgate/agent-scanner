package discovery

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
)

// getReadableHomeDirs returns all readable home directories on the system.
func getReadableHomeDirs() []string {
	switch runtime.GOOS {
	case "darwin":
		return getHomeDirsDarwin()
	case "linux":
		return getHomeDirsLinux()
	case "windows":
		return getHomeDirsWindows()
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		return []string{home}
	}
}

func getHomeDirsDarwin() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, home)
	}
	entries, err := os.ReadDir("/Users")
	if err != nil {
		return dirs
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "Shared" || name == ".localized" {
			continue
		}
		path := filepath.Join("/Users", name)
		if !isInDirs(path, dirs) && isReadable(path) {
			dirs = append(dirs, path)
		}
	}
	return dirs
}

func getHomeDirsLinux() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, home)
	}
	users := getSystemUsers()
	for _, u := range users {
		if u.HomeDir != "" && !isInDirs(u.HomeDir, dirs) && isReadable(u.HomeDir) {
			dirs = append(dirs, u.HomeDir)
		}
	}
	return dirs
}

func getHomeDirsWindows() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, home)
	}
	entries, err := os.ReadDir(`C:\Users`)
	if err != nil {
		return dirs
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "Public" || name == "Default" || name == "Default User" || name == "All Users" {
			continue
		}
		path := filepath.Join(`C:\Users`, name)
		if !isInDirs(path, dirs) && isReadable(path) {
			dirs = append(dirs, path)
		}
	}
	return dirs
}

func getSystemUsers() []*user.User {
	var users []*user.User
	for uid := 1000; uid < 65534; uid++ {
		u, err := user.LookupId(strconv.Itoa(uid))
		if err != nil {
			continue
		}
		users = append(users, u)
	}
	return users
}

func isReadable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func isInDirs(path string, dirs []string) bool {
	return slices.Contains(dirs, path)
}
