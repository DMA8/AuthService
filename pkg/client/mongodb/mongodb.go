package mongodb

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func MongoClient(ctx context.Context, connStr string) (*mongo.Client, error) {

	cOpts := options.Client().ApplyURI(connStr)
	mClient, err := mongo.Connect(ctx, cOpts)
	if err != nil {
		return nil, err
	}
	err = mClient.Ping(ctx, nil)

	if err != nil {
		log.Fatal(err)
	}
	return mClient, nil
}

func MongoCollection(mClient *mongo.Client, database, collection string) *mongo.Collection {
	return mClient.Database(database).Collection(collection)
}
