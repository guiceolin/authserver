package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/astaxie/beego/orm"
	jwt "github.com/dgrijalva/jwt-go"
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
	Id       int    `orm:"auto"`
	Name     string `orm:"size(100)"`
	Email    string `orm:"unique"`
	Password string
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

	type Claims struct {
		Id int `json:"id"`
		jwt.StandardClaims
	}
	return func(w http.ResponseWriter, r *http.Request) {

		requestDump, err := httputil.DumpRequest(r, true)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(string(requestDump))

		r.ParseForm()
		creds := Credentials{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		}

		user := User{Email: creds.Email}
		err = s.db.Read(&user, "Email")
		if err != nil {
			// If the structure of the body is wrong, return an HTTP error
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if user.Password != creds.Password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var jwtKey = []byte("my_secret_key")

		// Declare the expiration time of the token
		// here, we have kept it as 5 minutes
		expirationTime := time.Now().Add(5 * time.Minute)
		// Create the JWT claims, which includes the username and expiry time
		claims := &Claims{
			Id: user.Id,
			StandardClaims: jwt.StandardClaims{
				// In JWT, the expiry time is expressed as unix milliseconds
				ExpiresAt: expirationTime.Unix(),
			},
		}

		// Declare the token with the algorithm used for signing, and the claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// Create the JWT string
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			// If there is an error in creating the JWT return an internal server error
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Finally, we set the client cookie for "token" as the JWT we just generated
		// we also set an expiry time which is the same as the token itself
		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
			Domain:  "localhost",
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
	orm.RegisterModel(new(User))
	orm.RegisterDriver("postgres", orm.DRPostgres)
	orm.RegisterDataBase("default", "postgres", "user=postgres host=127.0.0.1 port=5432 dbname=authserver sslmode=disable")
	orm.RunSyncdb("default", false, true)

	viper.AutomaticEnv()
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

}

func main() {
	tmpl, err := template.ParseGlob("templates/**/*")
	if err != nil {
		log.Fatal(err)
	}
	s := server{
		router: httprouter.New(),
		db:     orm.NewOrm(),
		tmpl:   tmpl}
	s.routes()

	log.Fatal(http.ListenAndServe(":8080", s.router))
}
