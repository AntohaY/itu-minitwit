package app

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	. "minitwit/types"

	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// Global variables - exported for use by handlers
var Config Configuration
var DBClient *mongo.Client
var DB *mongo.Database
var Store = sessions.NewCookieStore([]byte("development key"))

// Constants
const PER_PAGE = 30

// Template function map
var FuncMap = template.FuncMap{
	"gravatar": func(email string) string {
		return GravatarURL(email)
	},
	"formatDate": func(timestamp int) string {
		return FormatDatetime(int64(timestamp))
	},
}

// GetUserID retrieves the user ID for a given username from the database
func GetUserID(username string) primitive.ObjectID {
	var result struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"username": username}
	err := DB.Collection("user").FindOne(ctx, filter).Decode(&result)
	if err != nil {
		return primitive.NilObjectID
	}
	return result.ID
}

// FormatDatetime converts a Unix timestamp to a formatted date string
func FormatDatetime(timestamp int64) string {
	timezone, _ := time.LoadLocation("Europe/Warsaw")
	t := time.Unix(timestamp, 0).In(timezone)
	return t.Format("2006-01-02 @ 15:04")
}

// GravatarURL generates a Gravatar URL for an email address
func GravatarURL(email string) string {
	cleanEmail := strings.ToLower(strings.TrimSpace(email))
	hash := md5.Sum([]byte(cleanEmail))
	hashString := hex.EncodeToString(hash[:])
	return fmt.Sprintf("http://www.gravatar.com/avatar/%s?d=identicon&s=%d", hashString, 80)
}

// CheckPasswordHash compares a plain password with a hashed password
func CheckPasswordHash(password, hashedPW string) bool {
	// TODO: implement proper password hashing comparison
	return password == hashedPW
}

// GetCurrentUser extracts the current user from the request context
func GetCurrentUser(r *http.Request) *User {
	val := r.Context().Value("user")
	if val == nil {
		return nil
	}

	user, ok := val.(User)
	if !ok {
		return nil
	}

	return &user
}

// RenderTemplate renders an HTML template with the given data
func RenderTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
	t := template.New("base").Funcs(FuncMap)

	t, err := t.ParseFiles("templates/layout.html", "templates/"+tmplName)
	if err != nil {
		log.Println("Parse Error:", err)
		http.Error(w, "Internal Error", 500)
		return
	}

	err = t.ExecuteTemplate(w, "base", data)
	if err != nil {
		log.Println("Exec Error:", err)
		http.Error(w, "Internal Error", 500)
	}
}

// QueryDatabaseForMessages retrieves public messages from the database
func QueryDatabaseForMessages(limit int) ([]Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := DB.Collection("message")

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{{Key: "flagged", Value: false}}}},
		{{Key: "$sort", Value: bson.D{{Key: "pub_date", Value: -1}}}},
		{{Key: "$limit", Value: limit}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "user"},
			{Key: "localField", Value: "author_id"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "author_info"},
		}}},
		{{Key: "$unwind", Value: "$author_info"}},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var messages []Message

	for cursor.Next(ctx) {
		var result struct {
			Text       string `bson:"text"`
			PubDate    int64  `bson:"pub_date"`
			Flagged    bool   `bson:"flagged"`
			AuthorInfo struct {
				Username string `bson:"username"`
				Email    string `bson:"email"`
			} `bson:"author_info"`
		}

		if err := cursor.Decode(&result); err != nil {
			return nil, err
		}

		messages = append(messages, Message{
			Text:     result.Text,
			PubDate:  int(result.PubDate),
			Username: result.AuthorInfo.Username,
		})
	}

	return messages, nil
}

// GetFollowedMessages retrieves messages from users that the given user follows
func GetFollowedMessages(userID primitive.ObjectID, limit int) ([]Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	followerColl := DB.Collection("follower")
	cursor, err := followerColl.Find(ctx, bson.M{"who_id": userID})
	if err != nil {
		return nil, err
	}

	followedIDs := []primitive.ObjectID{userID}

	for cursor.Next(ctx) {
		var rel struct {
			WhomID primitive.ObjectID `bson:"whom_id"`
		}
		if err := cursor.Decode(&rel); err == nil {
			followedIDs = append(followedIDs, rel.WhomID)
		}
	}
	cursor.Close(ctx)

	messageColl := DB.Collection("message")

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{
			{Key: "flagged", Value: false},
			{Key: "author_id", Value: bson.D{{Key: "$in", Value: followedIDs}}},
		}}},
		{{Key: "$sort", Value: bson.D{{Key: "pub_date", Value: -1}}}},
		{{Key: "$limit", Value: limit}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "user"},
			{Key: "localField", Value: "author_id"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "author_info"},
		}}},
		{{Key: "$unwind", Value: "$author_info"}},
	}

	cursor, err = messageColl.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var messages []Message
	for cursor.Next(ctx) {
		var result struct {
			Text       string `bson:"text"`
			PubDate    int64  `bson:"pub_date"`
			AuthorInfo struct {
				Username string `bson:"username"`
				Email    string `bson:"email"`
			} `bson:"author_info"`
		}

		if err := cursor.Decode(&result); err != nil {
			continue
		}

		messages = append(messages, Message{
			Text:     result.Text,
			PubDate:  int(result.PubDate),
			Username: result.AuthorInfo.Username,
		})
	}

	return messages, nil
}
