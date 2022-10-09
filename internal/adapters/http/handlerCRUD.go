package http

import (
	"fmt"
	"net/http"

	e "github.com/DMA8/authService/internal/domain/errors"

	"github.com/go-chi/chi"
)

// CreateUser godoc
// @Summary CreateUser
// @Description Creates user in db
// @Produce json
// @Success 200 {object} TestMessage
// @Router /user [post]
// @Accept       json
// @Produce      json
// @Param input body models.Credentials true "account info"
// CreateUser - handels POST /user
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	credentials, err := GetCredsFromCtx(r.Context())
	if err != nil {
		h.logger.Warn().Msgf("h.CreateUser err: %s", err.Error())
		WriteAnswer(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err = validateCreateCreds(credentials); err != nil {
		h.logger.Warn().Msgf("h.CreateUser err: %s", err.Error())
		WriteAnswer(w, http.StatusBadRequest, err.Error())
		return
	}
	err = h.auth.CreateUser(r.Context(), credentials)
	if err != nil {
		WriteAnswer(w, http.StatusInternalServerError, err.Error())
		return
	}
	WriteAnswer(w, http.StatusOK, fmt.Sprintf("user %s created", credentials.Login))
}

func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	login := chi.URLParam(r, "login")
	if login == "" {
		h.logger.Debug().Msg("h.GetUser no login")
		WriteAnswer(w, http.StatusBadRequest, "missed login")
		return
	}
	user, err := h.auth.GetUser(r.Context(), login)
	if err == e.ErrNoUserInDB {
		WriteAnswer(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		WriteAnswer(w, http.StatusInternalServerError, err.Error())
		return
	}
	WriteAnswer(w, http.StatusOK, fmt.Sprintf("userID %s userLogin %s", user.ID, user.Login))
}

func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	credentials, err := GetCredsFromCtx(r.Context())
	if err != nil {
		h.logger.Warn().Msgf("h.UpdateUser err: %s", err.Error())
		WriteAnswer(w, http.StatusInternalServerError, err.Error())
		return
	}
	err = h.auth.UpdateUser(r.Context(), credentials)
	if err == e.ErrNoUserInDB {
		WriteAnswer(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		WriteAnswer(w, http.StatusInternalServerError, err.Error())
		return
	}
	WriteAnswer(w, http.StatusOK, "update OK")
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	login := chi.URLParam(r, "login")
	if login == "" {
		h.logger.Debug().Msg("h.GetUser no login")
		WriteAnswer(w, http.StatusBadRequest, "missed login")
		return
	}
	err := h.auth.DeleteUser(r.Context(), login)
	if err == e.ErrNoUserInDB {
		WriteAnswer(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		WriteAnswer(w, http.StatusInternalServerError, err.Error())
		return
	}
	WriteAnswer(w, http.StatusOK, fmt.Sprintf("user %s deleted", login))
}
