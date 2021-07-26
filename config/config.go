package config

import (
	"io/ioutil"
	"os"
	"path"
)

const (
	App = "ztman"

	permissionsFile      = 0600
	permissionsDirectory = 0700
)

var (
	root string
)

func init() {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	root = path.Join(home, App)
	if err := Mkdir(root); err != nil {
		panic(err)
	}
}

func Path(elem ...string) string {
	return path.Join(append([]string{root}, elem...)...)
}

func Mkdir(dir string) error {
	return os.MkdirAll(dir, permissionsDirectory)
}

func WriteFile(file string, data []byte) error {
	return ioutil.WriteFile(file, data, permissionsFile)
}
