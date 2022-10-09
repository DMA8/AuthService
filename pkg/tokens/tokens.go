package tokens

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	ErrTokenCorrupted          = errors.New("jwt token is corrupted")
	ErrNoLoginTokenCreation    = errors.New("can not create token without login")
	ErrZeroDuration            = errors.New("token should live more then 0")
	ErrNoSecret                = errors.New("secret for token generation is not provided")
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method! shoud be jwt.SigningMethodHMAC")
	ErrBadClaimsInToken        = errors.New("error get user claims from token")
)

func CreateToken(login, secret string, dur time.Duration) (string, error) {
	switch {
	case secret == "":
		return "", ErrNoSecret
	case dur == 0:
		return "", ErrZeroDuration
	case login == "":
		return "", ErrNoLoginTokenCreation
	}
	tokenAccess := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(dur).Unix(),
		Subject:   login,
	})
	return tokenAccess.SignedString([]byte(secret))
}

func ValidateToken(tokenStr, secret string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrUnexpectedSigningMethod
		}
		return []byte(secret), nil
	})
	if err != nil {
		return "", err
	}
	if !token.Valid {
		return "", ErrTokenCorrupted
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", ErrBadClaimsInToken
	}
	return claims["sub"].(string), nil
}
