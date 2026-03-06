package types

import "go.mongodb.org/mongo-driver/bson/primitive"

type Message struct {
	ID        primitive.ObjectID `bson:"_id"`
	MessageID int                `bson:"message_id"`
	AuthorID  int                `bson:"author_id"`
	Text      string             `bson:"text"`
	PubDate   int                `bson:"pub_date"`
	Flagged   int                `bson:"flagged"`
	Username  string             `bson:"username"`
}