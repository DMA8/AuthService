package ports

import (
	"github.com/DMA8/authService/internal/domain/models"
	"context"
)

type AuthStorage interface {
	CreateUser(ctx context.Context, user *models.Credentials) error
	GetUser(ctx context.Context, login string) (*models.Credentials, error)
	UpdateUser(ctx context.Context, user *models.Credentials) error
	DeleteUser(ctx context.Context, login string) error
}
