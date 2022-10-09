package auth

import (
	"context"
	"errors"
	"time"

	"github.com/DMA8/authService/internal/config"
	e "github.com/DMA8/authService/internal/domain/errors"
	"github.com/DMA8/authService/internal/domain/models"
	"github.com/DMA8/authService/internal/ports"
	"github.com/DMA8/authService/pkg/logging"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/DMA8/authService/pkg/tokens"
)

type Auth struct {
	jwtcfg     config.JWTConfig
	repository ports.AuthStorage
	logger     logging.Logger
}

func NewAuth(cfg config.JWTConfig, repo ports.AuthStorage, l logging.Logger) *Auth {
	return &Auth{
		repository: repo,
		logger:     l,
		jwtcfg:     cfg,
	}
}

func (a *Auth) AuthUser(ctx context.Context, userData *models.Credentials) error {
	dbAnswer, err := a.repository.GetUser(ctx, userData.Login)
	if err != nil {
		a.logger.Debug().Err(err).Msgf("auth.AuthUser: couldn't get user from repo %+v", userData)
		return err
	}
	if goodPass := CheckPasswordHash(userData.Password, dbAnswer.Password); goodPass {
		return nil
	}
	a.logger.Debug().Err(err).Msgf("auth.AuthUser: wrong password inp:%+v, db:%+v", userData, dbAnswer)
	return e.ErrWrongPass
}

func (a *Auth) CreateToken(ctx context.Context, login string, tokenType models.TokenType) (string, error) {
	var dur time.Duration
	ctx, span := otel.Tracer("team31_auth").Start(ctx, "service auth CreateToken")
	span.SetAttributes(attribute.KeyValue{Key: "token_type", Value: attribute.StringValue(string(tokenType))})

	defer span.End()

	switch tokenType {
	case models.AccessTokenType:
		dur = a.jwtcfg.AccesTTL
	case models.RefreshTokenType:
		dur = a.jwtcfg.RefreshTTL
	default:
		a.logger.Debug().Err(nil).Msgf("service.CreateToken bad token type")
		return "", errors.New("wrong token type")
	}
	token, err := tokens.CreateToken(login, a.jwtcfg.Secret, dur)
	if err != nil {
		a.logger.Debug().Err(err).Msgf("service.CreateToken couldn't create token login: %s. tokenType %v ", login, tokenType)
	}
	a.logger.Debug().Err(err).Msgf("service.CreateToken tokent created! login: %s. tokenType %v ", login, tokenType)
	return token, err
}

// accepts token and if it is valid return login that should be encoded in token
func (a *Auth) ValidateToken(ctx context.Context, tokenStr string) (string, error) {
	ctx, span := otel.Tracer("team31_auth").Start(ctx, "service auth ValidateToken")
	span.SetAttributes(attribute.KeyValue{Key: "token", Value: attribute.StringValue(tokenStr)})
	defer span.End()
	login, err := tokens.ValidateToken(tokenStr, a.jwtcfg.Secret)
	if err != nil {
		a.logger.Debug().Err(err).Msgf("service.ValidateToken couldn't validate jwt tokens")
	}
	a.logger.Debug().Err(err).Msgf("service.ValidateToken token ok. login is %s", login)
	return login, err
}
