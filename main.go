package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/astaxie/beego/orm"
	_ "github.com/lib/pq"

	"github.com/julienschmidt/httprouter"
)

type server struct {
	router *httprouter.Router
	db     orm.Ormer
}

type User struct {
	Id       int    `orm:"auto"`
	Name     string `orm:"size(100)"`
	Email    string `orm:"unique"`
	Password string
}

func (s *server) routes() {
	s.router.HandlerFunc("GET", "/", s.handleIndex())
}

func (s *server) handleIndex() http.HandlerFunc {
	tmpl := template.Must(template.ParseFiles("./templates/index.html"))
	data := struct {
		CurrentUser *User
	}{}
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(data)
		tmpl.Execute(w, data)
	}
}

func init() {
	orm.RegisterModel(new(User))
	orm.RegisterDriver("postgres", orm.DRPostgres)
	orm.RegisterDataBase("default", "postgres", "user=postgres host=127.0.0.1 port=5432 dbname=authserver sslmode=disable")
	orm.RunSyncdb("default", false, true)
}

func main() {
	s := server{
		router: httprouter.New(),
		db:     orm.NewOrm()}
	s.routes()

	log.Fatal(http.ListenAndServe(":8080", s.router))
}
