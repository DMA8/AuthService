package ports

import (
	"github.com/DMA8/authService/internal/domain/models"
	"context"
)

//TODO: split into 2 interfaces. Auth and CRUD
type Auth interface {
	AuthUser(ctx context.Context, userData *models.Credentials) error
	CreateToken(ctx context.Context, login string, tokenType models.TokenType) (string, error)
	ValidateToken(ctx context.Context, tokenStr string) (string, error)

	CreateUser(ctx context.Context, userData *models.Credentials) error
	GetUser(ctx context.Context, login string) (*models.Credentials, error)
	UpdateUser(ctx context.Context, userData *models.Credentials) error
	DeleteUser(ctx context.Context, login string) error
}
