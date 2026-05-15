package types

type Message struct {
	Text     string `bson:"text"`
	PubDate  int    `bson:"pub_date"`
	Username string `bson:"username"`
}
