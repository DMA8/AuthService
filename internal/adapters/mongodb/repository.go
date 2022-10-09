package mongodb

import (
	"github.com/DMA8/authService/internal/config"
	"github.com/DMA8/authService/internal/domain/models"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	e "github.com/DMA8/authService/internal/domain/errors"
	"github.com/DMA8/authService/pkg/client/mongodb"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Repository struct {
	db *mongo.Collection
}

const (
	timeOut time.Duration = time.Second * 3 //may cause problems while debuging (set it more)
)

func NewRepository(ctx context.Context, cfg config.MongoConfig) (*Repository, error) {
	var connStr string
	ctx, _ = context.WithTimeout(ctx, timeOut)
	mongoPass := os.Getenv("MONGO_PASSWORD")
	if mongoPass == "" {
		log.Println("mongopass not found in env. applying config creds for mongo")
		connStr = fmt.Sprintf("mongodb://%s/%s", cfg.URI, cfg.DB)
	} else {
		connStr = fmt.Sprintf("mongodb://%s:%s@%s/%s", cfg.Login, mongoPass, cfg.URI, cfg.DB)
	}
	mongoCli, err := mongodb.MongoClient(ctx, connStr)
	if err != nil {
		return nil, err
	}
	if err = mongoCli.Ping(ctx, nil); err != nil {
		return nil, err
	}
	collection := mongodb.MongoCollection(mongoCli, cfg.DB, cfg.UserCollection)
	_, err = collection.Indexes().CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys:    bson.D{{Key: "login", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	)
	if err != nil {
		return nil, err
	}
	return &Repository{db: collection}, nil
}

func (r *Repository) CreateUser(ctx context.Context, user *models.Credentials) error {
	ctx, _ = context.WithTimeout(ctx, timeOut)
	_, err := r.db.InsertOne(ctx, user)
	return err
}

func (r *Repository) GetUser(ctx context.Context, login string) (*models.Credentials, error) {
	var user models.Credentials
	ctx, _ = context.WithTimeout(ctx, timeOut)
	if err := r.db.FindOne(ctx, bson.M{"login": login}).Decode(&user); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, e.ErrNoUserInDB
		}
		return nil, err
	}
	return &user, nil
}

func (r *Repository) UpdateUser(ctx context.Context, user *models.Credentials) error {
	ctx, _ = context.WithTimeout(ctx, timeOut)
	filter := bson.D{{"login", bson.D{{"$eq", user.Login}}}}
	update := bson.D{{"$set", bson.D{{"pswrd_hash", user.Password}}}}
	_, err := r.db.UpdateOne(ctx, filter, update)
	return err
}

func (r *Repository) DeleteUser(ctx context.Context, login string) error {
	ctx, _ = context.WithTimeout(ctx, timeOut)
	user, err := r.GetUser(ctx, login)
	if err != nil {
		return err
	}
	_, err = r.db.DeleteOne(ctx, bson.M{"_id": user.ID, "login": user.Login})
	return err
}
