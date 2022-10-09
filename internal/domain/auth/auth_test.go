package auth

import (
	"github.com/DMA8/authService/internal/config"
	e "github.com/DMA8/authService/internal/domain/errors"
	"github.com/DMA8/authService/internal/domain/models"
	"github.com/DMA8/authService/pkg/logging"
	mock_ports "github.com/DMA8/authService/internal/mocks"
	"context"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo"
)

func TestHashPassword(t *testing.T) {
	res, err := HashPassword("testPass")
	assert.NoError(t, err)
	assert.NotEmpty(t, res)
	res2, err := HashPassword("testPass2")
	assert.NoError(t, err)
	assert.NotEqual(t, res, res2)
}

func TestCheckPasswordHash(t *testing.T) {
	pass1 := "password"
	hashPass1, err := HashPassword(pass1)
	assert.NoError(t, err)
	assert.Equal(t, CheckPasswordHash(pass1, hashPass1), true)
	assert.Equal(t, CheckPasswordHash(pass1+"2", hashPass1), false)
	assert.Equal(t, CheckPasswordHash(pass1, hashPass1[:len(hashPass1)-2]), false)
}

func TestAuthUser(t *testing.T) {
	l := logging.New("debug")
	ctx := context.Background()
	cfg := config.JWTConfig{
		AccesTTL: time.Minute,
		RefreshTTL: time.Hour,
		Secret: "testSecret",
	}
	controller := gomock.NewController(t)
	defer controller.Finish()
	repoMock := mock_ports.NewMockAuthStorage(controller)
	auth := NewAuth(cfg, repoMock, l)

	//success auth:
	inputCreds := models.Credentials{
		Login:    "test1",
		Password: "test1",
	}
	testHash, err := HashPassword(inputCreds.Password)
	assert.NoError(t, err)
	dbAns := models.Credentials{
		Login:    "test1",
		Password: testHash,
	}
	repoMock.EXPECT().GetUser(gomock.Any(), inputCreds.Login).Return(&dbAns, nil).Times(1)
	authErr := auth.AuthUser(ctx, &inputCreds)
	assert.NoError(t, authErr)

	//no such login in DB
	inputCreds2 := models.Credentials{
		Login:    "test2",
		Password: "test2",
	}
	dbAns2 := models.Credentials{}
	repoMock.EXPECT().GetUser(gomock.Any(), inputCreds2.Login).Return(&dbAns2, mongo.ErrNoDocuments).Times(1)
	authErr2 := auth.AuthUser(ctx, &inputCreds2)
	assert.EqualError(t, authErr2, mongo.ErrNoDocuments.Error())

	//wrong password
	inputCreds3 := models.Credentials{
		Login:    "test3",
		Password: "test3",
	}
	testHash3, err := HashPassword(inputCreds3.Password)
	assert.NoError(t, err)
	dbAns3 := models.Credentials{
		Login:    "test3",
		Password: testHash3[:len(testHash3)-1] + "a",
	}
	repoMock.EXPECT().GetUser(gomock.Any(), inputCreds3.Login).Return(&dbAns3, nil).Times(1)
	authErr3 := auth.AuthUser(ctx, &inputCreds3)
	assert.Equal(t, e.ErrWrongPass, authErr3)
}

func TestCreateToken(t *testing.T) {
	TestCases := []struct {
		login    string
		expErr   error
	}{
		{
			expErr:   e.ErrNoLoginTokenCreation,
		},
	}
	cfg := config.JWTConfig{
		Secret: "test",
		AccesTTL: time.Minute,
		RefreshTTL: time.Hour,
	}
	cfg2 := config.JWTConfig{
		Secret: "test2",
		AccesTTL: time.Minute,
		RefreshTTL: time.Hour,
	}
	cfg3 := config.JWTConfig{
		Secret: "test2",
		AccesTTL: time.Minute * 2,
		RefreshTTL: time.Hour,
	}
	ctrl := gomock.NewController(t)
	repo := mock_ports.NewMockAuthStorage(ctrl)
	authService := NewAuth(cfg, repo, logging.New("debug"))
	authServiceDiffSecret := NewAuth(cfg2, repo, logging.New("debug"))
	authServiceDiffTTL := NewAuth(cfg3, repo, logging.New("debug"))

	ctx := context.Background()
	//testing errors
	for _, testCase := range TestCases {
		_, err := authService.CreateToken(ctx, testCase.login, models.AccessTokenType)
		assert.EqualError(t, err, testCase.expErr.Error())
	}
	//testing same inputs generates same outupts and diff inputs generates diff outputs
	token1, _ := authService.CreateToken(ctx, "test1", models.AccessTokenType)
	token2, _ := authService.CreateToken(ctx, "test1", models.AccessTokenType)
	assert.Equal(t, token1, token2)
	//ttl matter
	token1, _ = authService.CreateToken(ctx, "test", models.AccessTokenType)
	token2, _ = authServiceDiffTTL.CreateToken(ctx, "test1", models.AccessTokenType)
	assert.NotEqual(t, token1, token2)
	token1, _ = authService.CreateToken(ctx, "test1",  models.RefreshTokenType)
	token2, _ = authServiceDiffSecret.CreateToken(ctx, "test1", models.RefreshTokenType)
	assert.NotEqual(t, token1, token2)
	// secret matter
	token1, _ = authService.CreateToken(ctx, "test1",  models.AccessTokenType)
	token2, _ = authServiceDiffSecret.CreateToken(ctx, "test1", models.AccessTokenType)
	assert.NotEqual(t, token1, token2)

}

func TestValidateTokenOK(t *testing.T) {
	testCases := []struct {
		login         string
		salt          string
		duration      time.Duration
		token         string
		expectedLogin string
		expectedError error
	}{
		{
			login:         "admin",
			salt:          "salt",
			duration:      time.Minute,
			expectedLogin: "admin",
		},
		{
			login:         "1221edwqcvrewdscdfee12e 12e 2e 21 e32 r43 t5 23 1 2 12 12 3 3 31 123 123 1sdfwf32r 32r ",
			salt:          "2",
			duration:      time.Minute,
			expectedLogin: "1221edwqcvrewdscdfee12e 12e 2e 21 e32 r43 t5 23 1 2 12 12 3 3 31 123 123 1sdfwf32r 32r ",
		},
	}
	cfg := config.JWTConfig{
		Secret: "test",
		AccesTTL: time.Minute,
		RefreshTTL: time.Hour,
	}
	ctrl := gomock.NewController(t)
	repo := mock_ports.NewMockAuthStorage(ctrl)
	authService := NewAuth(cfg, repo, logging.New("debug"))
	ctx := context.Background()
	for _, testcase := range testCases {
		token, err := authService.CreateToken(ctx, testcase.login, models.AccessTokenType)
		testcase.token = token
		testcase.expectedError = err
		returnedLogin, returnedError := authService.ValidateToken(ctx, testcase.token)
		assert.NoError(t, returnedError)
		assert.Equal(t, returnedLogin, testcase.login)
	}
}

func TestValidateTokenErr(t *testing.T) {
	ctx := context.Background()
	cfg := config.JWTConfig{
		Secret: "test",
		AccesTTL: time.Minute,
		RefreshTTL: time.Hour,
	}
	expiredToken, err := createTokenTest("admin", time.Now().Add(-10 * time.Minute), cfg.Secret)
	assert.NoError(t, err)
	ctrl := gomock.NewController(t)
	repo := mock_ports.NewMockAuthStorage(ctrl)
	authService := NewAuth(cfg, repo, logging.New("debug"))
	login, err := authService.ValidateToken(ctx, expiredToken)
	assert.Equal(t, login, "")
	assert.EqualError(t, err, "Token is expired")

	corruptedToken, err := createTokenTest("admin", time.Now().Add(time.Minute*10), cfg.Secret)
	assert.NoError(t, err)
	login, err = authService.ValidateToken(ctx, corruptedToken[:30]+"YWRtaW4yCg"+corruptedToken[30:])
	assert.Equal(t, login, "")
	assert.Error(t, err)

	login, err = authService.CreateToken(ctx, "testLogin", models.TokenType("unexpected tokentype"))
	assert.Equal(t, login, "")
	assert.Error(t, err)

}

func createTokenTest(usrName string, time time.Time, secret string) (string, error) {
	if usrName == "" {
		return "", e.ErrNoLoginTokenCreation
	}
	tokenAccess := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Unix(),
		Subject:   usrName,
	})
	return tokenAccess.SignedString([]byte(secret))
}
