package jwt

import (
	"errors"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type claims struct {
	Payload map[string]interface{} `json:"payload"`
	jwt.StandardClaims
}

func BuildJWT(jwtKey []byte, payload map[string]interface{}, expirationTime time.Time) (string, error) {
	claims := &claims{
		Payload: payload,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	return tokenString, err
}

func ValidateJWT(jwtKey []byte, tknStr string) (map[string]interface{}, error) {
	claims := &claims{}
	_, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, errors.New("Invalid JWT Token")
		}
		return nil, err
	}

	return claims.Payload, nil
}
