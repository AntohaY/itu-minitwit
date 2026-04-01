package domains

import (
	"context"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Username string             `bson:"username"`
	Password string             `bson:"password"`
	Email    string             `bson:"email"`
	PW       string             `bson:"pw"`
	HashedPW string             `bson:"hashedpw"`
}

// contract for : registering user
type UserStore interface {
	Exists(ctx context.Context, username string) (bool, error)
	Create(ctx context.Context, user User) error
	GetUserByUsername(ctx context.Context, username string) (User, error)
}
