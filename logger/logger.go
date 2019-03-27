package logger

import (
	"log"
)

var LogLevel = "INFO"

func Info(v ...interface{}) {
	log.Print(v...)
}

func Debug(v ...interface{}) {
	if LogLevel == "DEBUG" {
		log.Print(v...)
	}
}

func Fatal(v ...interface{}) {
	log.Fatal(v...)
}
