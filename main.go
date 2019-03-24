package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

type server struct {
	router *httprouter.Router
}

func (s *server) routes() {
	s.router.HandlerFunc("GET", "/", s.handleIndex())
}

func (s *server) handleIndex() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello World!!!")
	}
}

func main() {
	s := server{router: httprouter.New()}
	s.routes()

	log.Fatal(http.ListenAndServe(":8080", s.router))
}
