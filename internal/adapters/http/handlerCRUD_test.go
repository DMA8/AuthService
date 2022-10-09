package http_test

import (
	p "github.com/DMA8/authService/internal/adapters/http"
	"github.com/DMA8/authService/internal/config"
	"github.com/DMA8/authService/internal/domain/models"
	"github.com/DMA8/authService/pkg/logging"
	mock_ports "github.com/DMA8/authService/internal/mocks"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestCreateUser(t *testing.T) {
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
	handler := http.HandlerFunc(handlerObj.CreateUser)

	rec := httptest.NewRecorder()
	reqBody := bytes.Buffer{}
	test := models.Credentials{
		Login:    "test1",
		Password: "test1",
	}
	marshalledCreds, err := json.Marshal(test)
	if err != nil {
		log.Fatal(err)
	}
	reqBody.Write(marshalledCreds)
	ctx := context.TODO()
	ctx = context.WithValue(ctx, p.CrudCreds, &test)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/createUser", cfg.HTTP.APIVersion), &reqBody)
	mockAuth.EXPECT().CreateUser(gomock.Any(), &test).Return(nil).Times(1)
	assert.NoError(t, err)
	handler.ServeHTTP(rec, request)
	var targets p.Message
	err = json.Unmarshal(rec.Body.Bytes(), &targets)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, targets.StatusCode)
	assert.Equal(t, true, strings.Contains(targets.Message, test.Login))

	rec2 := httptest.NewRecorder()
	reqBody2 := bytes.Buffer{}
	test2 := models.Credentials{
		Login:    "asdw",
		Password: "",
	}
	ctx2 := context.TODO()
	ctx2 = context.WithValue(ctx2, p.CrudCreds, &test2)
	marshalledCreds2, err := json.Marshal(test2)
	if err != nil {
		log.Fatal(err)
	}
	reqBody2.Write(marshalledCreds2)
	request2, err := http.NewRequestWithContext(ctx2, http.MethodPost, fmt.Sprintf("%s/createUser", cfg.HTTP.APIVersion), &reqBody2)
	assert.NoError(t, err)
	handler.ServeHTTP(rec2, request2)
	var targets2 p.Message
	err = json.Unmarshal(rec2.Body.Bytes(), &targets2)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, targets2.StatusCode)
}

func TestGetUser(t *testing.T) {
	cfg := &config.Config{
		HTTP: config.HTTPConfig{
			URI:               ":8080",
			AccessCookieName:  "access",
			RefreshCookieName: "refresh",
			APIVersion:        "/auth/v1",
		},
		JWT: config.JWTConfig{
			AccesTTL:   time.Minute,
			RefreshTTL: time.Hour,
		},
	}

	ctr := gomock.NewController(t)
	mockAuth := mock_ports.NewMockAuth(ctr)
	handlerObj := p.NewHandler(cfg.HTTP, mockAuth, logging.New("info"))
	handler := http.HandlerFunc(handlerObj.GetUser)

	rec := httptest.NewRecorder()
	reqBody := bytes.Buffer{}
	test := models.Credentials{
		Login: "test1",
	}
	expected := models.Credentials{
		Login:    test.Login,
		Password: "hashPass",
	}
	marshalledCreds, err := json.Marshal(test)
	if err != nil {
		log.Fatal(err)
	}
	reqBody.Write(marshalledCreds)
	ctx := context.WithValue(context.TODO(), p.CrudCreds, &test)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("login", test.Login)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/user/%s", cfg.HTTP.APIVersion, test.Login), nil)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, rctx))
	mockAuth.EXPECT().GetUser(request.Context(), test.Login).Return(&expected, nil).Times(1)
	assert.NoError(t, err)
	handler.ServeHTTP(rec, request)
	var targets p.Message
	err = json.Unmarshal(rec.Body.Bytes(), &targets)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, targets.StatusCode)
	assert.Equal(t, true, strings.Contains(targets.Message, test.Login))
	assert.Equal(t, true, strings.Contains(targets.Message, test.Password))

	rec2 := httptest.NewRecorder()
	reqBody2 := bytes.Buffer{}
	test2 := models.Credentials{}
	marshalledCreds2, err := json.Marshal(test2)
	if err != nil {
		log.Fatal(err)
	}
	reqBody.Write(marshalledCreds2)
	ctx2 := context.WithValue(context.TODO(), p.CrudCreds, &test2)
	request2, err := http.NewRequestWithContext(ctx2, http.MethodPost, fmt.Sprintf("%s/getUser", cfg.HTTP.APIVersion), &reqBody2)
	assert.NoError(t, err)
	handler.ServeHTTP(rec2, request2)
	var targets2 p.Message
	err = json.Unmarshal(rec2.Body.Bytes(), &targets2)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, targets2.StatusCode)
	assert.Equal(t, true, strings.Contains(targets2.Message, test2.Login))
	assert.Equal(t, true, strings.Contains(targets2.Message, test2.Password))
}

func TestUpdateUser(t *testing.T) {
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
	handler := http.HandlerFunc(handlerObj.UpdateUser)
	rec := httptest.NewRecorder()
	reqBody := bytes.Buffer{}
	test := models.Credentials{
		Login:    "test1",
		Password: "test1",
	}
	marshalledCreds, err := json.Marshal(test)
	if err != nil {
		log.Fatal(err)
	}
	reqBody.Write(marshalledCreds)
	ctx := context.WithValue(context.TODO(), p.CrudCreds, &test)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/updateUser", cfg.HTTP.APIVersion), &reqBody)
	mockAuth.EXPECT().UpdateUser(request.Context(), &test).Return(nil).Times(1)
	assert.NoError(t, err)
	handler.ServeHTTP(rec, request)
	var targets p.Message
	err = json.Unmarshal(rec.Body.Bytes(), &targets)
	assert.NoError(t, err)
}

func TestDeleteUser(t *testing.T) {
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
	handler := http.HandlerFunc(handlerObj.DeleteUser)
	rec := httptest.NewRecorder()
	reqBody := bytes.Buffer{}
	test := models.Credentials{
		Login: "test1",
	}
	marshalledCreds, err := json.Marshal(test)
	if err != nil {
		log.Fatal(err)
	}
	reqBody.Write(marshalledCreds)
	ctx := context.WithValue(context.TODO(), p.CrudCreds, &test)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("login", test.Login)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/deleteUser", cfg.HTTP.APIVersion), &reqBody)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, rctx))
	mockAuth.EXPECT().DeleteUser(request.Context(), test.Login).Return(nil).Times(1)
	assert.NoError(t, err)
	handler.ServeHTTP(rec, request)
	var targets p.Message
	err = json.Unmarshal(rec.Body.Bytes(), &targets)
	assert.NoError(t, err)
	assert.Equal(t, true, strings.Contains(targets.Message, test.Login))
}
