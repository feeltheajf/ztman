package logging

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// supported colors
const (
	colorBlack = iota + 30
	colorRed
	colorGreen
	colorYellow
	colorBlue
	colorMagenta
	colorCyan
	colorWhite

	colorBold     = 1
	colorDarkGray = 90
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
			return colorize("[T]", colorMagenta)
		case "debug":
			return colorize("[D]", colorCyan)
		case "info":
			return colorize("[I]", colorGreen)
		case "warn":
			return colorize("[W]", colorYellow)
		case "error":
			return colorize("[E]", colorRed)
		case "fatal":
			return colorize(colorize("[F]", colorRed), colorBold)
		case "panic":
			return colorize(colorize("[P]", colorRed), colorBold)
		}
	}
	return colorize("[?]", colorBold)
}

// colorize returns ANSI-colored strings
func colorize(message string, color int) string {
	return fmt.Sprintf("\x1b[%dm%s\x1b[0m", color, message)
}
