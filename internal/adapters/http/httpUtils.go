package http

import (
	"github.com/DMA8/authService/internal/domain/models"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
)

var (
	ErrBadCookies     error = errors.New("bad cookie")
	ErrBadCreateCreds error = errors.New("bad create creds")
	ErrBadCredsType   error = errors.New("bad creds type")
)

type Message struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
	IsError    bool   `json:"is_error"`
}

type TestMessage struct {
	StatusCode   int    `json:"status_code"`
	Message      string `json:"message"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func SetCookie(w http.ResponseWriter, cookieName, token, path string) {
	cookie := http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     path,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
}

func sendCookie(writer http.ResponseWriter, message, access, refresh string, status int) {
	msg := TestMessage{
		StatusCode:   status,
		Message:      message,
		AccessToken:  access,
		RefreshToken: refresh,
	}
	writer.WriteHeader(status)
	err := json.NewEncoder(writer).Encode(msg)
	if err != nil {
		log.Println("BAD json") //FIX ME
	}
}

func resetCookie(w http.ResponseWriter, cookieNames []string) {
	for _, cookieName := range cookieNames {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			MaxAge:   -1,
			Path:     "/",
			Expires:  time.UnixMicro(0),
			HttpOnly: true,
		})
	}
}

func initHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "application/json")
}

func GetCookieValue(cookies []string) (map[string]string, error) {
	if len(cookies) == 0 {
		return nil, ErrBadCookies
	}
	result := make(map[string]string)
	for _, v := range cookies {
		cookieFromLine := strings.Fields(v)
		for _, v := range cookieFromLine {
			delimIndex := strings.Index(v, "=")
			if delimIndex < 0 || delimIndex >= len(v)-1 {
				continue
			}
			result[v[:delimIndex]] = v[delimIndex+1:]
		}
	}
	return result, nil
}

func WriteAnswer(writer http.ResponseWriter, status int, message string) {
	var errorFlag bool
	if status >= 400 {
		errorFlag = true
	}
	msg := Message{
		StatusCode: status,
		Message:    message,
		IsError:    errorFlag,
	}
	writer.WriteHeader(status)
	err := json.NewEncoder(writer).Encode(msg)
	if err != nil {
		log.Println("BAD json") //FIX ME
	}
}

func getCredentials(r *http.Request) (*models.Credentials, error) {
	values := r.URL.Query()
	credentials := &models.Credentials{
		Login:    values.Get("login"),
		Password: values.Get("password"),
	}
	if credentials.Login == "" || credentials.Password == "" {
		r.ParseForm()
		credentials.Login = r.FormValue("login")
		credentials.Password = r.FormValue("password")
	}
	if credentials.Login == "" || credentials.Password == "" {
		err := json.NewDecoder(r.Body).Decode(&credentials)
		if err != nil {
			return nil, err
		}
	}
	if credentials.Login == "" || credentials.Password == "" {
		return nil, errors.New("bad input login/password")
	}
	return credentials, nil
}

func validateCreateCreds(creds *models.Credentials) error {
	if creds.Login == "" || creds.Password == "" {
		return ErrBadCreateCreds
	}
	return nil
}

func validateCreds(creds *models.Credentials) error {
	if creds.Login == "" {
		return ErrBadCreateCreds
	}
	return nil
}

func GetCredsFromCtx(ctx context.Context) (*models.Credentials, error) {
	credsFromCtx := ctx.Value(CrudCreds)
	switch credsFromCtx := credsFromCtx.(type) {
	case CredsCRUD, *models.Credentials:
		if credsFromCtx.(*models.Credentials).Login != "" {
			return credsFromCtx.(*models.Credentials), nil
		}
	}
	return nil, ErrBadCredsType
}

func GetReqID(ctx context.Context) string {
	return ctx.Value(RidKey).(string)
}
