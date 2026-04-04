package domains

import "go.mongodb.org/mongo-driver/bson/primitive"

type Follower struct {
	ID   primitive.ObjectID `bson:"_id,omitempty"`
	Who  primitive.ObjectID `bson:"who_id"`
	Whom primitive.ObjectID `bson:"whom_id"`
}
