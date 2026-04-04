package domains

import (
	"context"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// 1. Define the Interface
type FollowStore interface {
	Follow(ctx context.Context, whoID, whomID primitive.ObjectID) error
	Unfollow(ctx context.Context, whoID, whomID primitive.ObjectID) error
	IsFollowing(ctx context.Context, whoID, whomID primitive.ObjectID) (bool, error)
}
