package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/DMA8/authService/internal/domain/models"
	"github.com/DMA8/authService/pkg/logging"

	"github.com/go-chi/chi/v5/middleware"
	uuid "github.com/satori/go.uuid"
)

type UsrNameFromCtxtType string
type CredsCRUD string

const (
	NameInCtx UsrNameFromCtxtType = "name"
	CrudCreds CredsCRUD           = "creds"
)

type ctxKey int

const RidKey ctxKey = ctxKey(0)

func (h *Handler) checkToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var ctx context.Context
		cookies, err := GetCookieValue(req.Header["Cookie"])
		if err != nil {
			h.logger.Debug().Msgf("checkToken middleware. bad cookies! %+v", cookies)
			WriteAnswer(w, http.StatusForbidden, fmt.Sprintf("auth didn't succeed! bad cookies: %s", err))
			return
		}
		cfg := h.cfg
		if userName, err := h.auth.ValidateToken(ctx, cookies[cfg.AccessCookieName]); err == nil {
			ctx = context.WithValue(context.TODO(), NameInCtx, userName)
			h.logger.Debug().Msgf("checkToken middleware. access is alive")
			next.ServeHTTP(w, req.WithContext(ctx))
		} else if userName, err = h.auth.ValidateToken(ctx, cookies[cfg.RefreshCookieName]); err == nil {
			h.logger.Debug().Msgf("checkToken middleware. refresh is alive")
			ctx = context.WithValue(context.TODO(), NameInCtx, userName)
			accessToken, err := h.auth.CreateToken(ctx, userName, models.AccessTokenType)
			if err != nil {
				h.logger.Warn().Msgf("checkToken middleware. Сouldn't create accessToken! err: %s", err.Error())
				WriteAnswer(w, http.StatusInternalServerError, err.Error())
				return
			}
			refreshToken, err := h.auth.CreateToken(ctx, userName, models.RefreshTokenType)
			if err != nil {
				h.logger.Warn().Msgf("checkToken middleware. Сouldn't create refreshToken! err: %s", err.Error())
				WriteAnswer(w, http.StatusInternalServerError, err.Error())
				return
			}
			SetCookie(w, cfg.AccessCookieName, accessToken, "/")
			SetCookie(w, cfg.RefreshCookieName, refreshToken, "/")
			next.ServeHTTP(w, req.WithContext(ctx))
		} else {
			h.logger.Debug().Msg("checkToken middleware. dull jwt tokens")
			WriteAnswer(w, http.StatusForbidden, fmt.Sprintf("auth didn't succeed %s", err))
		}
	})
}

func Logger(l logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(rw http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(rw, r.ProtoMajor)
			start := time.Now()
			defer func() {
				Entry := &logging.Entry{
					Service:      "auth",
					Method:       r.Method,
					Url:          r.URL.Path,
					Query:        r.URL.RawQuery,
					RemoteIP:     r.RemoteAddr,
					Status:       ww.Status(),
					Size:         ww.BytesWritten(),
					ReceivedTime: start,
					Duration:     time.Since(start),
					ServerIP:     r.Host,
					UserAgent:    r.Header.Get("User-Agent"),
					RequestId:    GetReqID(r.Context()),
				}
				l.Info().Msgf("%+v", *Entry)
			}()
			next.ServeHTTP(ww, r)
		}
		return http.HandlerFunc(fn)
	}
}

func (h *Handler) profilingCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var profilingEnabled bool
		h.mu.Lock()
		profilingEnabled = h.ProfEnabled
		h.mu.Unlock()
		if profilingEnabled {
			next.ServeHTTP(w, r)
		} else {
			WriteAnswer(w, http.StatusForbidden, "profiling is switched off")
		}
	})
}

func (h *Handler) validateInput(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ctx context.Context
		var credentials models.Credentials
		err := json.NewDecoder(r.Body).Decode(&credentials)
		if err != nil {
			h.logger.Debug().Msgf("validateInput middleware. bad input err: %s", err.Error())
			WriteAnswer(w, http.StatusBadRequest, err.Error())
			return
		}
		err = validateCreds(&credentials)
		if err != nil {
			h.logger.Debug().Msgf("validateInput middleware. couldn't validate creds %+v err: %s", credentials, err.Error())
			WriteAnswer(w, http.StatusBadRequest, err.Error())
			return
		}
		ctx = context.WithValue(context.TODO(), CrudCreds, &credentials)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-ID")
		if rid == "" {
			rid = uuid.NewV4().String()
		}
		ctx := context.WithValue(r.Context(), RidKey, rid)
		w.Header().Add("X-Request-ID", rid)

		next.ServeHTTP(w, r.WithContext(ctx))
	}))
}
