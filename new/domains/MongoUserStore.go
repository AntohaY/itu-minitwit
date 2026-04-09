package domains

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// 1. The Real Database Struct
type MongoUserStore struct {
	DB *mongo.Database
}

// 2. Implement the Interface Methods

func (m *MongoUserStore) Exists(ctx context.Context, username string) (bool, error) {
	// Count how many users have this username
	count, err := m.DB.Collection("user").CountDocuments(ctx, bson.M{"username": username})
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (m *MongoUserStore) Create(ctx context.Context, user User) error {
	// Insert the user into Mongo
	_, err := m.DB.Collection("user").InsertOne(ctx, user)
	return err
}

func (m *MongoUserStore) GetUserByUsername(ctx context.Context, username string) (User, error) {
	var foundUser User
	// Find the user by username
	err := m.DB.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&foundUser)
	return foundUser, err
}

func (m *MongoUserStore) GetUserByID(ctx context.Context, id primitive.ObjectID) (User, error) {
	var user User
	err := m.DB.Collection("user").FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	return user, err
}
