package jwt

import (
	"errors"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spf13/viper"
)

type Payload struct {
	Id    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Claims struct {
	Payload `json:"payload"`
	jwt.StandardClaims
}

var jwtKey = []byte(viper.GetString("jwt_secret"))

func BuildJWT(payload Payload, expirationTime time.Time) (string, error) {
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

func ValidateJWT(tknStr string) (*Payload, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, errors.New("Invalid JWT Token")
		}
		return nil, err
	}

	return &claims.Payload, nil
}
