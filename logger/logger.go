package logger

import (
	"log"
	"net/http"
	"net/http/httputil"
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

func LogRequest(r *http.Request) {
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		Info(err)
	}
	Info(string(requestDump))
}
