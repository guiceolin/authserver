package logger

import (
	"log"
	"os"
)

var logLevel = "INFO"

func init() {
	if value, ok := os.LookupEnv("LOG_LEVEL"); ok {
		logLevel = value
	}
}

func Info(v ...interface{}) {
	log.Print(v...)
}

func Debug(v ...interface{}) {
	if logLevel == "DEBUG" {
		log.Print(v...)
	}
}

func Fatal(v ...interface{}) {
	log.Fatal(v...)
}
