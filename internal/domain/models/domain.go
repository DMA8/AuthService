package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type TokenType string

const (
	AccessTokenType TokenType = "access"
	RefreshTokenType TokenType = "refresh"
)

type Credentials struct {
	ID       primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Login    string             `json:"login" bson:"login"`
	Password string             `json:"password" bson:"pswrd_hash"`
}
