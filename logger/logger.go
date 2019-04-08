package logger

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"time"
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

func RequestMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		Info(fmt.Sprintf("Started %s %s for %s at %s", r.Method, r.URL, r.RemoteAddr, start.Format(time.RFC3339)))
		h.ServeHTTP(w, r)
		total := time.Since(start)
		Info(fmt.Sprintf("Completed in %s", total))

	})
}
