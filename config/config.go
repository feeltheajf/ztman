package config

import (
	"os"
	"path"
	"runtime"

	"github.com/feeltheajf/ztman/fs"
)

const (
	App = "ztman"
	Sht = runtime.GOOS == "windows"
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
	if err := fs.Mkdir(root); err != nil {
		panic(err)
	}
}

func Path(elem ...string) string {
	return path.Join(append([]string{root}, elem...)...)
}
