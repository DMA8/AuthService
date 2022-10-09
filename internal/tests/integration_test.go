//go:build integration
// +build integration

package integrationtest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"
	
	"github.com/stretchr/testify/suite"
	
	entrypoint "github.com/DMA8/authService/internal/adapters/http"
	repository "github.com/DMA8/authService/internal/adapters/mongodb"
	"github.com/DMA8/authService/internal/config"
	"github.com/DMA8/authService/internal/domain/auth"
	"github.com/DMA8/authService/internal/domain/models"
	logger "github.com/DMA8/authService/pkg/logging"
)

type integraTestSuite struct {
	suite.Suite

	cfg    *config.Config
	logger logger.Logger
	r      *repository.Repository
	app    *http.Server
}

func TestIntegraTestSuite(t *testing.T) {
	suite.Run(t, &integraTestSuite{})
}

func testConfig() *config.Config {
	cfg := config.Config{
		HTTP: config.HTTPConfig{
			URI:               ":3001",
			RefreshCookieName: "refreshToken",
			AccessCookieName:  "accessToken",
			APIVersion:        "/auth/v1",
		},
		JWT: config.JWTConfig{
			Secret:     "secret",
			AccesTTL:   time.Minute,
			RefreshTTL: time.Hour,
		},
		Mongo: config.MongoConfig{
			URI:            "localhost:27017",
			URIFul:         "mongodb://localhost:27017",
			UserCollection: "usersTest",
			DB:             "test",
		},
		Log: config.LogConfig{Level: "debug"},
	}
	return &cfg
}

func (s *integraTestSuite) SetupSuite() {
	cfg := testConfig()
	s.cfg = cfg
	ctx, _ := context.WithCancel(context.Background())
	l := logger.New(cfg.Log.Level)
	s.logger = l
	repo, err := repository.NewRepository(ctx, cfg.Mongo)
	if err != nil {
		l.Fatal().Err(err)
	}
	s.r = repo
	l.Info().Msg("Hello server")
	authService := auth.NewAuth(s.cfg.JWT, repo, l)
	handler := entrypoint.NewHandler(cfg.HTTP, authService, l)
	server := entrypoint.NewHTTPServer(cfg.HTTP, handler)
	s.app = server
	go server.ListenAndServe()
}

// Positive case - для разраба
// negative case - для тестировщика

func (s *integraTestSuite) TestScenario() {
	//1. создаем пользователя
	testUserCreate := models.Credentials{
		Login:    "test1",
		Password: "pass1",
	}
	reqBody := bytes.Buffer{}
	marshalledBody, err := json.Marshal(testUserCreate)
	if err != nil {
		log.Fatal(err)
	}
	reqBody.Write(marshalledBody)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost%s%s/user", s.app.Addr, s.cfg.HTTP.APIVersion), &reqBody)
	s.NoError(err)
	client := http.Client{}
	response, err := client.Do(req)
	s.NoError(err)
	s.Equal(http.StatusOK, response.StatusCode)
	var msg entrypoint.Message
	s.NoError(json.NewDecoder(response.Body).Decode(&msg))
	s.Equal(http.StatusOK, msg.StatusCode)
	s.Contains(msg.Message, testUserCreate.Login)
	response.Body.Close()
	testGetUser := models.Credentials{
		Login: testUserCreate.Login,
	}

	//2. Читаем созданного выше пользователя
	req2, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost%s%s/user/%s", s.app.Addr, s.cfg.HTTP.APIVersion, testUserCreate.Login), nil)
	s.NoError(err)
	client2 := http.Client{}
	response2, err := client2.Do(req2)
	s.NoError(err)
	s.Equal(http.StatusOK, response2.StatusCode)
	var msg2 entrypoint.Message
	s.NoError(json.NewDecoder(response2.Body).Decode(&msg2))
	s.Equal(http.StatusOK, msg2.StatusCode)
	s.Contains(msg2.Message, testGetUser.Login)
	response2.Body.Close()

	//3. Логинимся с кредами пользователя выше
	req3, err := http.NewRequest("POST", fmt.Sprintf("http://localhost%s%s/login?login=%s&password=%s", s.app.Addr, s.cfg.HTTP.APIVersion, testUserCreate.Login, testUserCreate.Password), nil)
	s.NoError(err)
	client3 := http.Client{}
	response3, err := client3.Do(req3)
	s.NoError(err)
	log.Println(response3.Body)
	s.Equal(http.StatusOK, response3.StatusCode)
	var msg3 entrypoint.Message
	s.NoError(json.NewDecoder(response3.Body).Decode(&msg3))
	s.Equal(http.StatusOK, msg3.StatusCode)

	//тест кук
	req4, err := http.NewRequest("GET", fmt.Sprintf("http://localhost%s%s/i", s.app.Addr, s.cfg.HTTP.APIVersion), nil)
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	client4 := http.Client{Jar: jar}
	client4.Jar.SetCookies(req4.URL, response3.Cookies())
	response4, err := client4.Do(req4)
	s.NoError(err)
	log.Println(response4.Body)
	s.Equal(http.StatusOK, response4.StatusCode)
	var msg4 entrypoint.Message
	s.NoError(json.NewDecoder(response4.Body).Decode(&msg4))
	s.Equal(http.StatusOK, msg4.StatusCode)

	//логаут
	req5, err := http.NewRequest("GET", fmt.Sprintf("http://localhost%s%s/logout", s.app.Addr, s.cfg.HTTP.APIVersion), nil)
	response5, err := client4.Do(req5)
	s.NoError(err)
	log.Println(response5.Body)
	s.Equal(http.StatusOK, response5.StatusCode)
	var msg5 entrypoint.Message
	s.NoError(json.NewDecoder(response5.Body).Decode(&msg5))
	s.Equal(http.StatusOK, msg5.StatusCode)
	s.Equal(response5.Cookies()[0].Name, s.cfg.HTTP.AccessCookieName)
	s.Equal(response5.Cookies()[0].Expires, time.UnixMicro(0).UTC())
	s.Equal(response5.Cookies()[1].Name, s.cfg.HTTP.RefreshCookieName)
	s.Equal(response5.Cookies()[1].Expires, time.UnixMicro(0).UTC())
}

//MongoCruds
func (s *integraTestSuite) TestRepo() {
	ctx := context.TODO()
	usr1 := models.Credentials{
		Login:    "test6123!!",
		Password: "pass",
	}
	err := s.r.CreateUser(ctx, &usr1)
	s.NoError(err)
	usrControl, err := s.r.GetUser(ctx, usr1.Login)
	s.NoError(err)
	s.Equal(usr1.Login, usrControl.Login)
	s.Equal(usr1.Password, usrControl.Password)

	_, err = s.r.GetUser(ctx, "no such login in repo")
	s.Error(err)

	usr1Updated := models.Credentials{
		ID:       usrControl.ID,
		Login:    usr1.Login,
		Password: strings.ToUpper(usr1.Password),
	}
	err = s.r.UpdateUser(ctx, &usr1Updated)
	s.NoError(err)
	updUser, err := s.r.GetUser(ctx, usr1Updated.Login)
	s.NoError(err)
	s.Equal(usr1.Login, updUser.Login)
	s.Equal(strings.ToUpper(usr1.Password), updUser.Password)

	err = s.r.DeleteUser(ctx, updUser.Login)
	s.NoError(err)
	_, err = s.r.GetUser(ctx, updUser.Login)
	s.Error(err)
}
