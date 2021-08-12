package fs

import (
	"io/ioutil"
	"os"
)

const (
	permissionsFile      = 0600
	permissionsDirectory = 0700
)

// Read is a convenience wrapper around `ioutil.ReadFile`
func Read(filename string) (string, error) {
	b, err := ioutil.ReadFile(filename) // #nosec: G304
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Write is a convenience wrapper around `ioutil.WriteFile`
func Write(filename string, data string) error {
	return ioutil.WriteFile(filename, []byte(data), permissionsFile)
}

// Mkdir is a convenience wrapper around `os.MkdirAll`
func Mkdir(path string) error {
	return os.MkdirAll(path, permissionsDirectory)
}
