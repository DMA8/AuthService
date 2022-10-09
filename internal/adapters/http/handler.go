package http

import (
	e "github.com/DMA8/authService/internal/domain/errors"
	"github.com/DMA8/authService/internal/domain/models"
	"fmt"
	"net/http"
)

// Login godoc
// @Summary Login with basic auth
// @Description It accepts parameters from basic auth and return access and refresh tokens
// @Produce json
// @Success 200 {object} TestMessage
// @Router /login [post]
// @Accept       json
// @Produce      json
// @Param input body models.Credentials true "account info"
// Login - handels /login. It accepts parameters from basic auth
// or parses htmlform (finds there "Login" and "pasword")
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	initHeaders(w)
	credentials, err := getCredentials(r)
	if err != nil {
		h.logger.Debug().Msgf("h.Login. couldn't get creds %+v, err: %s", credentials, err.Error())
		WriteAnswer(w, http.StatusBadRequest, err.Error())
		return
	}
	AuthErr := h.auth.AuthUser(r.Context(), credentials)
	if AuthErr != nil {
		switch AuthErr {
		case e.ErrNoUserInDB:
			WriteAnswer(w, http.StatusNotFound, AuthErr.Error())
			return
		case e.ErrWrongPass:
			WriteAnswer(w, http.StatusForbidden, AuthErr.Error())
			return
		}
		WriteAnswer(w, http.StatusInternalServerError, AuthErr.Error())
		return
	}
	accessToken, err := h.auth.CreateToken(r.Context(), credentials.Login, models.AccessTokenType)
	if err != nil {
		h.logger.Warn().Msgf("h.Login couldn't create accessToken %s", err.Error())
		WriteAnswer(w, http.StatusInternalServerError, err.Error())
		return
	}
	SetCookie(w, h.cfg.AccessCookieName, accessToken, "/")
	refreshToken, err := h.auth.CreateToken(r.Context(), credentials.Login, models.RefreshTokenType)
	if err != nil {
		h.logger.Warn().Msgf("h.Login couldn't create refreshToken %s", err.Error())
		WriteAnswer(w, http.StatusInternalServerError, err.Error())
		return
	}
	SetCookie(w, h.cfg.RefreshCookieName, refreshToken, "/")
	sendCookie(w, "OK", accessToken, refreshToken, http.StatusOK)
}

// Logout godoc
// @Summary removes client's access and refresh tokens
// @Description It accepts token and return user login if token is alive
// @Router /logout [get]
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	initHeaders(w)
	resetCookie(w, []string{h.cfg.AccessCookieName, h.cfg.RefreshCookieName})
	WriteAnswer(w, http.StatusOK, "cookies removed successfully")
}

// I godoc
// @Summary check token
// @Description It accepts token and return user login if token is alive
// @Router /i [get]
func (h *Handler) I(w http.ResponseWriter, r *http.Request) {
	initHeaders(w)
	usr := r.Context().Value(NameInCtx)
	switch usr := usr.(type) {
	case UsrNameFromCtxtType, string:
		WriteAnswer(w, http.StatusOK, fmt.Sprintf("Hi %s!, your jwt tokens are perfect!", usr))
	default:
		WriteAnswer(w, http.StatusInternalServerError, "Unexpected type of user from context")
	}
}

func (h *Handler) Profiling(w http.ResponseWriter, r *http.Request) {
	var profilingInputState bool
	var answer string
	
	values := r.URL.Query()
	toggle := values.Get("state")
	if toggle == "on" {
		profilingInputState = true
		answer = "profiling is on"
	} else if toggle == "off" {
		profilingInputState = false
		answer = "profiling is off"
	} else {
		WriteAnswer(w, http.StatusBadRequest, "there are only to options in ?state: on and off")
		return
	}
	h.mu.Lock()
	h.ProfEnabled = profilingInputState
	h.mu.Unlock()
	WriteAnswer(w, http.StatusOK, answer)
}
