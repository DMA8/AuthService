package http_test

import (
	"github.com/DMA8/authService/internal/config"
	"github.com/DMA8/authService/internal/domain/models"
	"github.com/DMA8/authService/pkg/logging"
	p "github.com/DMA8/authService/internal/adapters/http"
	e "github.com/DMA8/authService/internal/domain/errors"
	mock_ports "github.com/DMA8/authService/internal/mocks"
	"github.com/DMA8/authService/pkg/tokens"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestHandlerLogin(t *testing.T) {
	cfg := &config.Config{
		HTTP: config.HTTPConfig{
			URI:               ":8080",
			AccessCookieName:  "access",
			RefreshCookieName: "refresh",
		},
		JWT: config.JWTConfig{
			Secret: "test",
			AccesTTL:   time.Minute,
			RefreshTTL: time.Hour,
		},
	}
	ctr := gomock.NewController(t)
	mockAuth := mock_ports.NewMockAuth(ctr)
	handlerObj := p.NewHandler(cfg.HTTP, mockAuth, logging.New("info"))
	handler := http.HandlerFunc(handlerObj.Login)
	rec := httptest.NewRecorder()
	reqBody := bytes.Buffer{}
	ctx := context.Background()
	test := models.Credentials{
		Login:    "test1",
		Password: "test1",
	}
	request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/login?login=%s&password=%s", cfg.HTTP.APIVersion, test.Login, test.Password), &reqBody)
	assert.NoError(t, err)
	mockAuth.EXPECT().AuthUser(request.Context(), &test).Return(nil).Times(1)
	mockAuth.EXPECT().CreateToken(ctx, test.Login, models.AccessTokenType).Return(tokens.CreateToken(test.Login, cfg.JWT.Secret, cfg.JWT.AccesTTL)).Times(1)
	mockAuth.EXPECT().CreateToken(ctx, test.Login, models.RefreshTokenType).Return(tokens.CreateToken(test.Login, cfg.JWT.Secret, cfg.JWT.AccesTTL)).Times(1)

	handler.ServeHTTP(rec, request)
	response := rec.Result()
	cookies := response.Cookies()
	var targets p.Message
	err = json.Unmarshal(rec.Body.Bytes(), &targets)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, targets.StatusCode)
	assert.Equal(t, false, targets.IsError)
	assert.Equal(t, true, len(cookies) > 1)
	assert.Equal(t, true, cookies[0].Name == cfg.HTTP.AccessCookieName)
	assert.Equal(t, true, cookies[1].Name == cfg.HTTP.RefreshCookieName)

	loginFromCookie, err := tokens.ValidateToken(cookies[0].Value, cfg.JWT.Secret)
	assert.NoError(t, err)
	assert.Equal(t, true, loginFromCookie == test.Login)
	assert.Equal(t, true, cookies[0].Name == cfg.HTTP.AccessCookieName)

	loginFromCookie, err = tokens.ValidateToken(cookies[1].Value, cfg.JWT.Secret)
	assert.NoError(t, err)
	assert.Equal(t, true, loginFromCookie == test.Login)
	assert.Equal(t, true, cookies[1].Name == cfg.HTTP.RefreshCookieName)

	test2 := models.Credentials{
		Login:    "test1",
		Password: "",
	}
	rec2 := httptest.NewRecorder()
	var targets2 p.Message
	reqBody2 := bytes.Buffer{}
	request2, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/login?login=%s&password=%s", cfg.HTTP.APIVersion, test2.Login, test2.Password), &reqBody2)
	assert.NoError(t, err)
	handler.ServeHTTP(rec2, request2)

	err = json.Unmarshal(rec2.Body.Bytes(), &targets2)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, targets2.StatusCode)
	assert.Equal(t, true, targets2.IsError)

	test3 := models.Credentials{
		Login:    "",
		Password: "asd2",
	}
	rec3 := httptest.NewRecorder()
	var targets3 p.Message
	reqBody3 := bytes.Buffer{}
	request3, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/login?login=%s&password=%s", cfg.HTTP.APIVersion, test3.Login, test3.Password), &reqBody3)
	assert.NoError(t, err)
	handler.ServeHTTP(rec3, request3)

	err = json.Unmarshal(rec3.Body.Bytes(), &targets3)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, targets3.StatusCode)
	assert.Equal(t, true, targets3.IsError)

	//wrong pass or user not exists
	test4 := models.Credentials{
		Login:    "NoUser",
		Password: "WrongPass",
	}
	mockAuth.EXPECT().AuthUser(request.Context(), &test4).Return(e.ErrNoUserInDB).Times(1)
	rec4 := httptest.NewRecorder()
	var targets4 p.Message
	reqBody4 := bytes.Buffer{}
	request4, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/login?login=%s&password=%s", cfg.HTTP.APIVersion, test4.Login, test4.Password), &reqBody4)
	assert.NoError(t, err)
	handler.ServeHTTP(rec4, request4)

	err = json.Unmarshal(rec4.Body.Bytes(), &targets4)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, targets4.StatusCode)
	assert.Equal(t, true, targets4.IsError)


	mockAuth.EXPECT().AuthUser(request.Context(), &test4).Return(e.ErrWrongPass).Times(1)
	rec5 := httptest.NewRecorder()
	var targets5 p.Message
	reqBody5 := bytes.Buffer{}
	request5, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/login?login=%s&password=%s", cfg.HTTP.APIVersion, test4.Login, test4.Password), &reqBody5)
	assert.NoError(t, err)
	handler.ServeHTTP(rec5, request5)

	err = json.Unmarshal(rec5.Body.Bytes(), &targets5)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, targets5.StatusCode)
	assert.Equal(t, true, targets5.IsError)
}

func TestHandlerLogout(t *testing.T) {
	cfg := &config.Config{
		HTTP: config.HTTPConfig{
			URI:               ":8080",
			AccessCookieName:  "access",
			RefreshCookieName: "refresh",
		},
		JWT: config.JWTConfig{
			AccesTTL:   time.Minute,
			RefreshTTL: time.Hour,
		},
	}
	var targets p.Message
	ctr := gomock.NewController(t)
	mockAuth := mock_ports.NewMockAuth(ctr)
	handlerObj := p.NewHandler(cfg.HTTP, mockAuth, logging.New("debug"))
	handler := http.HandlerFunc(handlerObj.Logout)
	rec := httptest.NewRecorder()
	reqBody := bytes.Buffer{}
	request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/logout", cfg.HTTP.APIVersion), &reqBody)
	assert.NoError(t, err)
	handler.ServeHTTP(rec, request)
	err = json.Unmarshal(rec.Body.Bytes(), &targets)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, targets.StatusCode)
	response := rec.Result()
	cookies := response.Cookies()
	assert.Equal(t, cfg.HTTP.AccessCookieName, cookies[0].Name)
	assert.Equal(t, cfg.HTTP.RefreshCookieName, cookies[1].Name)
	assert.Equal(t, time.UnixMicro(0), cookies[0].Expires.Local())
	assert.Equal(t, time.UnixMicro(0), cookies[1].Expires.Local())
}

func TestHandlerI(t *testing.T) {
	var targets p.Message
	testName1 := "admin"
	cfg := &config.Config{
		HTTP: config.HTTPConfig{
			URI:               ":8080",
			AccessCookieName:  "access",
			RefreshCookieName: "refresh",
		},
		JWT: config.JWTConfig{
			AccesTTL:   time.Minute,
			RefreshTTL: time.Hour,
		},
	}
	ctr := gomock.NewController(t)
	mockAuth := mock_ports.NewMockAuth(ctr)
	handlerObj := p.NewHandler(cfg.HTTP, mockAuth, logging.New("debug"))
	handler := http.HandlerFunc(handlerObj.I)
	rec := httptest.NewRecorder()
	reqBody := bytes.Buffer{}
	ctx := context.WithValue(context.TODO(), p.NameInCtx, p.UsrNameFromCtxtType(testName1))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/i", cfg.HTTP.APIVersion), &reqBody)
	assert.NoError(t, err)
	handler.ServeHTTP(rec, request)
	err = json.Unmarshal(rec.Body.Bytes(), &targets)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, targets.StatusCode)
	assert.Equal(t, true, strings.Contains(targets.Message, testName1))

	//test with empty context
	var targets2 p.Message
	reqBody2 := bytes.Buffer{}
	ctx2 := context.TODO()
	rec2 := httptest.NewRecorder()

	request2, err := http.NewRequestWithContext(ctx2, http.MethodGet, fmt.Sprintf("%s/i", cfg.HTTP.APIVersion), &reqBody2)
	assert.NoError(t, err)
	handler.ServeHTTP(rec2, request2)
	err = json.Unmarshal(rec2.Body.Bytes(), &targets2)
	assert.NoError(t, err)
}

func TestHandlerProfiling(t *testing.T) {
	var targets p.Message
	cfg := &config.Config{
		HTTP: config.HTTPConfig{
			URI:               ":8080",
			AccessCookieName:  "access",
			RefreshCookieName: "refresh",
		},
		JWT: config.JWTConfig{
			AccesTTL:   time.Minute,
			RefreshTTL: time.Hour,
		},
	}
	ctr := gomock.NewController(t)
	mockAuth := mock_ports.NewMockAuth(ctr)
	handlerObj := p.NewHandler(cfg.HTTP, mockAuth, logging.New("debug"))
	handler := http.HandlerFunc(handlerObj.Profiling)

	//switching on profiling
	rec := httptest.NewRecorder()
	reqBody := bytes.Buffer{}
	state := "on"
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/profswitch?state=%s", cfg.HTTP.APIVersion, state), &reqBody)
	assert.NoError(t, err)
	handler.ServeHTTP(rec, request)
	err = json.Unmarshal(rec.Body.Bytes(), &targets)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, targets.StatusCode)
	assert.Equal(t, true, handlerObj.ProfEnabled)

	//switching off profiling from off state
	rec2 := httptest.NewRecorder()
	reqBody2 := bytes.Buffer{}
	state = "off"
	request2, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/profswitch?state=%s", cfg.HTTP.APIVersion, state), &reqBody2)
	assert.NoError(t, err)
	handler.ServeHTTP(rec2, request2)
	err = json.Unmarshal(rec2.Body.Bytes(), &targets)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, targets.StatusCode)
	assert.Equal(t, false, handlerObj.ProfEnabled)
	test2ProffState := handlerObj.ProfEnabled

	//bad command in off state
	rec3 := httptest.NewRecorder()
	reqBody3 := bytes.Buffer{}
	state = "o2f"
	request3, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/profswitch?state=%s", cfg.HTTP.APIVersion, state), &reqBody3)
	assert.NoError(t, err)
	handler.ServeHTTP(rec3, request3)
	err = json.Unmarshal(rec3.Body.Bytes(), &targets)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, targets.StatusCode)
	assert.Equal(t, test2ProffState, handlerObj.ProfEnabled) // state hasn't been changed
}

