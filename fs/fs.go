package fs

import (
	"os"
)

const (
	permissionsFile      = 0600
	permissionsDirectory = 0700
)

// Read is a convenience wrapper around `os.ReadFile`
func Read(filename string) (string, error) {
	b, err := os.ReadFile(filename) // #nosec: G304
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Write is a convenience wrapper around `os.WriteFile`
func Write(filename string, data string) error {
	return os.WriteFile(filename, []byte(data), permissionsFile)
}

// Mkdir is a convenience wrapper around `os.MkdirAll`
func Mkdir(path string) error {
	return os.MkdirAll(path, permissionsDirectory)
}
