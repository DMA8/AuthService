package auth

import (
	"github.com/DMA8/authService/internal/domain/models"
	"context"
)

func (a *Auth) CreateUser(ctx context.Context, userData *models.Credentials) error {
	passwordHash, err := HashPassword(userData.Password)
	if err != nil {
		a.logger.Debug().Err(err).Msgf("auth.CreateUser: couldn't create passwordHash %+v", userData)
		return err
	}
	userData.Password = passwordHash
	err = a.repository.CreateUser(ctx, userData)
	if err != nil {
		a.logger.Debug().Err(err).Msgf("auth.CreateUser: couldn't create user %+v", userData)
	}
	return err
}

func (a *Auth) GetUser(ctx context.Context, login string) (*models.Credentials, error) {
	creds, err := a.repository.GetUser(ctx, login)
	if err != nil {
		a.logger.Debug().Msgf("auth.GetUser: couldn't get user %+v", login)
	}
	return creds, err
}

func (a *Auth) UpdateUser(ctx context.Context, userData *models.Credentials) error {
	hash, err := HashPassword(userData.Password)
	if err != nil {
		return err
	}
	userData.Password = hash
	err = a.repository.UpdateUser(ctx, userData)
	if err != nil {
		a.logger.Debug().Err(err).Msgf("auth.UpdateUser couldn't update user %+v", userData)
	}
	return err
}

func (a *Auth) DeleteUser(ctx context.Context, login string) error {
	err := a.repository.DeleteUser(ctx, login)
	if err != nil {
		a.logger.Debug().Err(err).Msgf("auth.Delete couldn't delete user %+v", login)
	}
	return err
}
