package logging

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/feeltheajf/ztman/config"
)

// Setup initializes global logging subsystem
func Setup(level zerolog.Level) {
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(
		zerolog.ConsoleWriter{
			Out:     os.Stderr,
			NoColor: config.Sht,
		},
	)
}
