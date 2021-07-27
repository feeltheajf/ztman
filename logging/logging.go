package logging

import (
	"os"

	"github.com/fatih/color"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Setup initializes global logging subsystem
func Setup(level zerolog.Level) {
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(
		zerolog.ConsoleWriter{
			Out:         os.Stderr,
			FormatLevel: consoleFormatLevel,
		},
	)
}

// consoleFormatLevel is a custom log formatter for prettier text logs
func consoleFormatLevel(level interface{}) string {
	if levelString, ok := level.(string); ok {
		switch levelString {
		case "trace":
			return color.MagentaString("[T]")
		case "debug":
			return color.CyanString("[D]")
		case "info":
			return color.GreenString("[I]")
		case "warn":
			return color.YellowString("[W]")
		case "error":
			return color.RedString("[E]")
		case "fatal":
			return color.New(color.FgRed, color.Bold).Sprint("[F]")
		case "panic":
			return color.New(color.FgRed, color.Bold).Sprint("[P]")
		}
	}
	return color.New(color.Bold).Sprint("[?]")
}
