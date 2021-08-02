package logging

import (
	"os"

	"github.com/fatih/color"
	"github.com/manifoldco/promptui"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/feeltheajf/ztman/config"
)

// Setup initializes global logging subsystem
func Setup(level zerolog.Level) {
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(
		zerolog.ConsoleWriter{
			Out:         os.Stderr,
			NoColor:     config.Sht,
			FormatLevel: formatLevel,
		},
	)
}

func formatLevel(level interface{}) string {
	if levelString, ok := level.(string); ok {
		switch levelString {
		case "trace":
			return promptui.Styler(promptui.FGMagenta)("[T]")
		case "debug":
			return colorize("[D]", color.FgCyan)
		case "info":
			return colorize("[I]", color.FgGreen)
		case "warn":
			return colorize("[W]", color.FgYellow)
		case "error":
			return promptui.Styler(promptui.FGRed)("[E]")
		case "fatal":
			return colorize("[F]", color.FgRed, color.Bold)
		case "panic":
			return colorize("[P]", color.FgRed, color.Bold)
		}
	}
	return colorize("[?]", color.Bold)
}

func colorize(s string, c ...color.Attribute) string {
	if config.Sht {
		return s
	}
	return color.New(c...).Sprint(s)
}
