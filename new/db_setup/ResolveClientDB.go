package db_setup

import (
	"context"
	"log/slog"
	"time"

	. "minitwit/types"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func ResolveClientDB(config Configuration) (*mongo.Client, *mongo.Database) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	uri := config.MongoURI
	if uri == "" {
		uri = "mongodb://dbserver:27017"
	}

	clientOpts := options.Client().ApplyURI(uri)

	dbClient, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		slog.Error("mongo connect error", "error", err.Error())
		panic("mongo connect error")
	}

	if err := dbClient.Ping(ctx, nil); err != nil {
		slog.Error("mongo ping error", "error", err.Error())
		panic("mongo ping error")
	}

	db := dbClient.Database("test")

	if err := ensureIndexes(db); err != nil {
		slog.Error("failed to ensure indexes", "error", err.Error())
		panic("failed to ensure indexes")
	}

	return dbClient, db
}

func ensureIndexes(db *mongo.Database) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := db.Collection("user").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return err
	}

	_, err = db.Collection("follower").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "who_id", Value: 1}, {Key: "whom_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "who_id", Value: 1}},
		},
	})
	if err != nil {
		return err
	}

	_, err = db.Collection("message").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "flagged", Value: 1}, {Key: "pub_date", Value: -1}},
		},
		{
			Keys: bson.D{{Key: "author_id", Value: 1}, {Key: "flagged", Value: 1}, {Key: "pub_date", Value: -1}},
		},
	})
	if err != nil {
		return err
	}

	return nil
}
