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

func (s User) checkPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(s.EncryptedPassword), []byte(password))
	if err != nil {
		return false
	}
	return true
}

func (s *User) encryptPassword() error {
	saltedPass, err := bcrypt.GenerateFromPassword([]byte(s.Password), 10)
	if err != nil {
		return err
	}
	s.EncryptedPassword = string(saltedPass)
	return nil
}

func (s *User) validate(db orm.Ormer) bool {
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

func setRedirectUrl(w http.ResponseWriter, r *http.Request) {
	redirectTo := r.URL.Query().Get("redirect_to")
	if redirectTo != "" {
		c := &http.Cookie{
			Name:    "redirectTo",
			Value:   redirectTo,
			Path:    "/",
			Expires: time.Now().Add(1 * time.Hour),
			Domain:  viper.GetString("domain"),
		}

		http.SetCookie(w, c)
	}
}

func getRedirectBackURL(w http.ResponseWriter, r *http.Request) *string {
	redirectToFromParam := r.URL.Query().Get("redirect_to")
	if redirectToFromParam != "" {
		return &redirectToFromParam
	}
	redirectToCookie, err := r.Cookie("redirectTo")
	if err == nil {
		return &redirectToCookie.Value

	}

	return nil
}

func redirectBackOrTo(w http.ResponseWriter, r *http.Request, redirectTo string) {
	c := &http.Cookie{
		Name:   "redirectTo",
		Path:   "/",
		MaxAge: -1,
		Domain: viper.GetString("domain"),
	}

	http.SetCookie(w, c)

	redirectBackUrl := getRedirectBackURL(w, r)
	if redirectBackUrl != nil {
		redirectTo = *redirectBackUrl
	}

	http.Redirect(w, r, redirectTo, http.StatusSeeOther)
}

func renderWithTemplate(w http.ResponseWriter, templateName string, data interface{}) {
	templateFile := fmt.Sprintf("templates/%s", templateName)
	tmpl, err := template.New("").ParseFiles(templateFile, "templates/layout.html")
	if err != nil {
		logger.Fatal(err)
	}
	tmpl.ExecuteTemplate(w, "base", data)
}

func setCurrentUser(w http.ResponseWriter, user User) {
	var expirationTime = time.Now().Add(5 * time.Hour)

	payload := map[string]interface{}{
		"id":    user.Id,
		"name":  user.Name,
		"email": user.Email,
	}
	var jwtKey = []byte(viper.GetString("jwt_secret"))
	tokenString, err := jwt.BuildJWT(jwtKey, payload, expirationTime)
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

func isAuthenticated(r *http.Request) bool {
	c, err := r.Cookie("token")
	if err != nil {
		return false
	}

	var jwtKey = []byte(viper.GetString("jwt_secret"))
	_, err = jwt.ValidateJWT(jwtKey, c.Value)
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

	var jwtKey = []byte(viper.GetString("jwt_secret"))
	payload, err := jwt.ValidateJWT(jwtKey, c.Value)
	if err != nil {
		return nil
	}

	user := User{
		Id: int(payload["id"].(float64)),
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
		if isAuthenticated(r) {
			redirectBackOrTo(w, r, "/")
			return
		}

		setRedirectUrl(w, r)

		renderWithTemplate(w, "users_new.html", nil)
	}
}

func (s *server) handleCreateUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isAuthenticated(r) {
			redirectBackOrTo(w, r, "/")
			return
		}

		setRedirectUrl(w, r)

		r.ParseForm()

		user := User{
			Name:                 r.FormValue("name"),
			Email:                r.FormValue("email"),
			Password:             r.FormValue("password"),
			PasswordConfirmation: r.FormValue("password_confirmation"),
		}

		if user.validate(s.db) {
			user.encryptPassword()
			_, err := s.db.Insert(&user)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			setCurrentUser(w, user)
			redirectBackOrTo(w, r, "/")
			return
		}

		renderWithTemplate(w, "users_new.html", user)
	}
}

func (s *server) handleCreateSession() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		if isAuthenticated(r) {
			redirectBackOrTo(w, r, "/")
			return
		}

		r.ParseForm()

		user := User{Email: r.FormValue("email")}
		err := s.db.Read(&user, "Email")
		if err == nil && user.checkPassword(r.FormValue("password")) {
			setCurrentUser(w, user)

			redirectBackOrTo(w, r, "/")
			return

		} else {
			data := struct {
				Error string
			}{
				Error: "Invalid Credentials",
			}

			renderWithTemplate(w, "session_new.html", data)
			return

		}
	}
}

func (s *server) handleNewSession() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isAuthenticated(r) {
			redirectBackOrTo(w, r, "/")
			return
		}

		setRedirectUrl(w, r)

		renderWithTemplate(w, "session_new.html", nil)
	}
}

func (s *server) handleDeleteSession() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAuthenticated(r) {
			redirectBackOrTo(w, r, "/")
			return
		}

		c := &http.Cookie{
			Name:   "token",
			Path:   "/",
			MaxAge: -1,
			Domain: viper.GetString("domain"),
		}

		http.SetCookie(w, c)
		redirectBackOrTo(w, r, "/")
	}
}

func (s *server) handleIndex() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectBackUrl := getRedirectBackURL(w, r)
		if redirectBackUrl != nil && isAuthenticated(r) {
			redirectBackOrTo(w, r, "/")
		}

		setRedirectUrl(w, r)

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

	logger.Fatal(http.ListenAndServe(":"+viper.GetString("port"), logger.RequestMiddleware(s.router)))
}
