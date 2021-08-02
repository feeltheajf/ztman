package logging

import (
	"fmt"
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
			Out:                 os.Stderr,
			NoColor:             true,
			PartsExclude:        []string{zerolog.TimestampFieldName},
			FormatLevel:         formatLevel,
			FormatFieldName:     formatFieldName,
			FormatErrFieldName:  formatErrFieldName,
			FormatErrFieldValue: formatErrFieldValue,
		},
	)
}

func formatLevel(level interface{}) string {
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

func formatFieldName(i interface{}) string {
	return color.CyanString(fmt.Sprintf("%s=", i))
}

func formatErrFieldName(i interface{}) string {
	return color.RedString(fmt.Sprintf("%s=", i))
}

func formatErrFieldValue(i interface{}) string {
	return color.RedString(fmt.Sprintf("%s", i))
}
