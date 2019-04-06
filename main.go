package main

import (
	"fmt"
	"github.com/astaxie/beego/orm"
	"github.com/guiceolin/authserver/jwt"
	"github.com/guiceolin/authserver/logger"
	_ "github.com/lib/pq"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
	"regexp"
	"time"

	"github.com/julienschmidt/httprouter"
)

type server struct {
	router *httprouter.Router
	db     orm.Ormer
	tmpl   *template.Template
}

type User struct {
	Id                   int               `orm:"auto" json:"id"`
	Name                 string            `orm:"size(100)" json:"name"`
	Email                string            `orm:"unique" json:"email"`
	EncryptedPassword    string            `json:"-"`
	Password             string            `json:"-" orm:"-"`
	PasswordConfirmation string            `json:"-" orm:"-"`
	Errors               map[string]string `json:"-" orm:"-"`
}

func (s User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(s.EncryptedPassword), []byte(password))
	if err != nil {
		return false
	}
	return true
}

func (s *User) EncryptPassword() error {
	saltedPass, err := bcrypt.GenerateFromPassword([]byte(s.Password), 10)
	if err != nil {
		return err
	}
	s.EncryptedPassword = string(saltedPass)
	return nil
}

func (s *User) Validate(db orm.Ormer) bool {
	s.Errors = make(map[string]string)

	if s.Email == "" {
		s.Errors["Email"] = "Can't be blank"
	}

	Re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	if !Re.MatchString(s.Email) {
		s.Errors["Email"] = "Is invalid"
	}

	if db.QueryTable("user").Filter("email", s.Email).Exist() {
		s.Errors["Email"] = "Already taken"
	}

	if s.Password == "" {
		s.Errors["Password"] = "Can't be blank"
	}

	if s.Password != s.PasswordConfirmation {
		s.Errors["PasswordConfirmation"] = "Must be equals password"
	}

	if s.PasswordConfirmation == "" {
		s.Errors["PasswordConfirmation"] = "Can't be blank"
	}

	if s.Name == "" {
		s.Errors["Name"] = "Can't be blank"
	}

	return len(s.Errors) == 0
}

func renderWithTemplate(w http.ResponseWriter, templateName string, data interface{}) {
	templateFile := fmt.Sprintf("templates/%s", templateName)
	tmpl, err := template.New("").ParseFiles(templateFile, "templates/layout.html")
	if err != nil {
		logger.Fatal(err)
	}
	tmpl.ExecuteTemplate(w, "base", data)
}

func SetCurrentUser(w http.ResponseWriter, user User) {
	var expirationTime = time.Now().Add(5 * time.Hour)

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
		Path:    "/",
		Expires: expirationTime,
		Domain:  viper.GetString("domain"),
	})

}

func IsAuthenticated(r *http.Request) bool {
	c, err := r.Cookie("token")
	if err != nil {
		return false
	}

	_, err = jwt.ValidateJWT(c.Value)
	if err != nil {
		return false
	}
	return true
}

func (s *server) getCurrentUser(r *http.Request) *User {
	c, err := r.Cookie("token")
	if err != nil {
		return nil
	}

	payload, err := jwt.ValidateJWT(c.Value)
	if err != nil {
		return nil
	}

	user := User{
		Id: payload.Id,
	}
	err = s.db.Read(&user)
	if err != nil {
		return nil
	}

	return &user
}

func (s *server) routes() {
	s.router.HandlerFunc("GET", "/", s.handleIndex())
	s.router.HandlerFunc("GET", "/sessions/new", s.handleNewSession())
	s.router.HandlerFunc("POST", "/sessions", s.handleCreateSession())
	s.router.HandlerFunc("GET", "/sessions/destroy", s.handleDeleteSession())

	s.router.HandlerFunc("GET", "/users/new", s.handleNewUser())
	s.router.HandlerFunc("POST", "/users", s.handleCreateUser())
}

func (s *server) handleNewUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.LogRequest(r)

		if IsAuthenticated(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		renderWithTemplate(w, "users_new.html", nil)
	}
}

func (s *server) handleCreateUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.LogRequest(r)

		if IsAuthenticated(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		r.ParseForm()

		user := User{
			Name:                 r.FormValue("name"),
			Email:                r.FormValue("email"),
			Password:             r.FormValue("password"),
			PasswordConfirmation: r.FormValue("password_confirmation"),
		}

		if user.Validate(s.db) {
			user.EncryptPassword()
			_, err := s.db.Insert(&user)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			SetCurrentUser(w, user)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		logger.Info(user.Errors)
		renderWithTemplate(w, "users_new.html", user)
	}
}

func (s *server) handleCreateSession() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		logger.LogRequest(r)

		if IsAuthenticated(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

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

		SetCurrentUser(w, user)

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
}

func (s *server) handleNewSession() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if IsAuthenticated(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		renderWithTemplate(w, "session_new.html", nil)
	}
}

func (s *server) handleDeleteSession() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsAuthenticated(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		c := &http.Cookie{
			Name:   "token",
			Path:   "/",
			MaxAge: -1,
			Domain: viper.GetString("domain"),
		}

		http.SetCookie(w, c)
		http.Redirect(w, r, "/", http.StatusSeeOther)

	}
}

func (s *server) handleIndex() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			CurrentUser *User
		}{
			CurrentUser: s.getCurrentUser(r),
		}
		renderWithTemplate(w, "index.html", data)
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
	s := server{
		router: httprouter.New(),
		db:     orm.NewOrm()}
	s.routes()

	logger.Fatal(http.ListenAndServe(":"+viper.GetString("port"), s.router))
}
