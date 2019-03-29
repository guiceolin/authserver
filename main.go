package main

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/astaxie/beego/orm"
	jwt "github.com/dgrijalva/jwt-go"
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

func buildJWT(payload interface{}, expirationTime time.Time) (string, error) {
	type Claims struct {
		Payload interface{} `json:"payload"`
		jwt.StandardClaims
	}

	var jwtKey = []byte(viper.GetString("jwt_secret"))
	claims := &Claims{
		Payload: payload,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	return tokenString, err

}

func (s *server) routes() {
	s.router.HandlerFunc("GET", "/", s.handleIndex())
	s.router.HandlerFunc("GET", "/sessions/new", s.handleNewSession())
	s.router.HandlerFunc("POST", "/sessions", s.handleCreateSession())
}

func (s *server) handleCreateSession() http.HandlerFunc {
	type Credentials struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	var expirationTime = time.Now().Add(5 * time.Minute)

	return func(w http.ResponseWriter, r *http.Request) {
		logger.LogRequest(r)

		r.ParseForm()
		creds := Credentials{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		}

		user := User{Email: creds.Email}
		err := s.db.Read(&user, "Email")
		if err != nil {
			// If the structure of the body is wrong, return an HTTP error
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if user.Password != creds.Password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		tokenString, err := buildJWT(user, expirationTime)
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
