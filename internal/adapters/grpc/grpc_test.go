package grpc_test

import (
	"context"
	"testing"
	"time"

	"github.com/DMA8/authService/internal/domain/models"
	"github.com/DMA8/authService/internal/adapters/grpc"
	"github.com/DMA8/authService/internal/config"
	"github.com/DMA8/authService/internal/domain/auth"
	"github.com/DMA8/authService/pkg/logging"
	mock_ports "github.com/DMA8/authService/internal/mocks"
	"github.com/DMA8/authService/pkg/grpc_auth"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	ctx := context.TODO()
	l := logging.New("debug")
	cfgGRPC := config.GRPCConfig{
		URI:       ":10000",
		Transport: "tcp",
	}
	jwtConfig := config.JWTConfig{
		Secret:     "test",
		AccesTTL:   time.Minute,
		RefreshTTL: time.Hour,
	}
	ctr := gomock.NewController(t)
	mockRepo := mock_ports.NewMockAuthStorage(ctr)
	authBussiness := auth.NewAuth(jwtConfig, mockRepo, l)
	serv := grpc.NewAuthServer(cfgGRPC, authBussiness, l)
	serv.LaunchGRPCServer()

	token1Access, err := authBussiness.CreateToken(ctx, "admin", models.AccessTokenType)
	require.NoError(t, err)
	token1Refresh, err := authBussiness.CreateToken(ctx, "admin", models.RefreshTokenType)
	require.NoError(t, err)

	test1 := grpc_auth.Credential{
		AccessToken:  token1Access,
		RefreshToken: token1Refresh,
	}
	resp, err := serv.Validate(ctx, &test1)
	require.NoError(t, err)
	assert.Equal(t, true, resp.Success)
	assert.Equal(t, false, resp.IsUpdate)

	test2 := grpc_auth.Credential{
		RefreshToken: token1Refresh,
	}
	resp2, err := serv.Validate(ctx, &test2)
	require.NoError(t, err)
	assert.Equal(t, true, resp2.Success)
	assert.Equal(t, true, resp2.IsUpdate)
}
