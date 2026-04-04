package domains

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type MongoFollowStore struct {
	DB *mongo.Database
}

func (m *MongoFollowStore) Follow(ctx context.Context, whoID, whomID primitive.ObjectID) error {
	follow := Follower{
		Who:  whoID,
		Whom: whomID,
	}
	_, err := m.DB.Collection("follow").InsertOne(ctx, follow)
	return err
}

func (m *MongoFollowStore) Unfollow(ctx context.Context, whoID, whomID primitive.ObjectID) error {
	_, err := m.DB.Collection("follow").DeleteOne(ctx, bson.M{"who_id": whoID, "whom_id": whomID})
	return err
}

func (m *MongoFollowStore) IsFollowing(ctx context.Context, whoID, whomID primitive.ObjectID) (bool, error) {
	count, err := m.DB.Collection("follow").CountDocuments(ctx, bson.M{"who_id": whoID, "whom_id": whomID})
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
