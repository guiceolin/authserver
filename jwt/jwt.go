package jwt

import (
	"errors"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spf13/viper"
)

type Claims struct {
	Payload interface{} `json:"payload"`
	jwt.StandardClaims
}

var jwtKey = []byte(viper.GetString("jwt_secret"))

func BuildJWT(payload interface{}, expirationTime time.Time) (string, error) {
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

func ValidateJWT(tknStr string) (interface{}, error) {
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, errors.New("Invalid JWT Token")
		}
		return nil, err
	}

	return tkn, nil
}
