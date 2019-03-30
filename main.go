package main

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/astaxie/beego/orm"
	"github.com/guiceolin/authserver/jwt"
	"github.com/guiceolin/authserver/logger"
	_ "github.com/lib/pq"
	"github.com/spf13/viper"

	"github.com/julienschmidt/httprouter"
)

type server struct {
	router *httprouter.Router
	db     orm.Ormer
	tmpl   *template.Template
}

type User struct {
	Id       int    `orm:"auto" json:"id"`
	Name     string `orm:"size(100)" json:"name"`
	Email    string `orm:"unique" json:"email"`
	Password string `json:"-"`
}

func (s User) CheckPassword(password string) bool {
	return s.Password == password
}

func (s *server) routes() {
	s.router.HandlerFunc("GET", "/", s.handleIndex())
	s.router.HandlerFunc("GET", "/sessions/new", s.handleNewSession())
	s.router.HandlerFunc("POST", "/sessions", s.handleCreateSession())
}

func (s *server) handleCreateSession() http.HandlerFunc {
	var expirationTime = time.Now().Add(5 * time.Minute)

	return func(w http.ResponseWriter, r *http.Request) {
		logger.LogRequest(r)

		r.ParseForm()

		user := User{Email: r.FormValue("email")}
		err := s.db.Read(&user, "Email")
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if !user.CheckPassword(r.FormValue("password")) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		payload := jwt.Payload{
			Id:    user.Id,
			Name:  user.Name,
			Email: user.Email,
		}
		tokenString, err := jwt.BuildJWT(payload, expirationTime)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
			Domain:  viper.GetString("domain"),
		})

	}
}

func (s *server) handleNewSession() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.tmpl.ExecuteTemplate(w, "sessions/new", nil)

	}
}

func (s *server) handleIndex() http.HandlerFunc {
	data := struct {
		CurrentUser *User
	}{}
	return func(w http.ResponseWriter, r *http.Request) {
		s.tmpl.ExecuteTemplate(w, "index", data)
	}
}

func init() {
	viper.AutomaticEnv()
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()

	logger.LogLevel = viper.GetString("log_level")

	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
	orm.RegisterModel(new(User))
	orm.RegisterDriver("postgres", orm.DRPostgres)
	orm.RegisterDataBase("default", "postgres", viper.GetString("database_url"))
	orm.RunSyncdb("default", false, true)
}

func main() {
	tmpl, err := template.ParseGlob("templates/**/*")
	if err != nil {
		logger.Fatal(err)
	}
	s := server{
		router: httprouter.New(),
		db:     orm.NewOrm(),
		tmpl:   tmpl}
	s.routes()

	logger.Fatal(http.ListenAndServe(":"+viper.GetString("port"), s.router))
}
