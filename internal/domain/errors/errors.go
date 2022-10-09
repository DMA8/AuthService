package errors

import "errors"

var (
	ErrNoUserInDB error = errors.New("couldn't find the user")
	ErrWrongPass error = errors.New("bad password")
	ErrBadCreds error = errors.New("bad creds")

	ErrTokenCorrupted = errors.New("jwt token is corrupted")
	ErrNoLoginTokenCreation = errors.New("can not create token without login")
	ErrZeroDuration = errors.New("token should live more then 0")
)
