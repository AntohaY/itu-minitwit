//commands to check functionality

//1. you can do docker composition
//docker-compose up --build
//docker composition is set for port 5001! -> http://localhost:5001

//2. do it manually but than don't do step 1
//start a temporary database
//docker run --name my-test-mongo -p 27017:27017 -d mongo:latest

//check if docker container is runing
//docker ps
//if not, than start it
//docker start my-test-mongo

//download valid dependencies
//go mod tidy

//check if it works
//go run main.go

package main

import (
	"context"
	"crypto/md5"
	"encoding/base64" // needed for manual flash cookies
	"encoding/hex"    // needed for gravatar
	"fmt"
	"html/template" // <--- Added this
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/gorilla/sessions"
)

type Configuration struct {
	Debug     bool
	SecretKey string
	MongoURI  string
}

type User struct {
	ID       primitive.ObjectID `bson:"_id"`
	Username string             `bson:"username"`
	Email    string             `bson:"email"`
}

type BaseContext struct {
	User    *User    // Wraps the current user (replaces g.user)
	Flashes []string // Replaces get_flashed_messages()
}

// 2. The Specific Page Data embeds the Base
type TimelinePage struct {
	BaseContext // Embeds User and Flashes automatically
	Messages    []TimelineMessage
	ProfileUser *User
	PageTitle   string // Needed for {{ .PageTitle }}
	PageID      string // Needed for "active" tab logic (public vs user)
}

type TimelineMessage struct {
	MessageID int
	AuthorID  int
	Text      string
	PubDate   int // or time.Time
	Flagged   bool
	Username  string // From the joined User table
	Email     string // From the joined User table

}

type TimelineData struct {
	PageTitle   string // Replaces self.title() logic
	PageID      string // Replaces request.endpoint logic ("public", "user", "personal")
	Messages    []TimelineMessage
	ProfileUser *User // Can be nil if not on a user profile
	CurrentUser *User // Represents g.user
	IsFollowing bool  // Replaces 'followed' boolean
}

var config Configuration
var dbClient *mongo.Client
var db *mongo.Database
var store = sessions.NewCookieStore([]byte("development key"))

func main() {
	config = Configuration{
		Debug:     true,
		SecretKey: "development key",
	}

	if envKey := os.Getenv("SECRET_KEY"); envKey != "" {
		config.SecretKey = envKey
	}

	dbIP := os.Getenv("DB_IP")
	if dbIP == "" {
		dbIP = "localhost" // Fallback if running outside Docker
	}
	config.MongoURI = fmt.Sprintf("mongodb://%s:27017", dbIP)

	fmt.Println("Connecting to:", config.MongoURI)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(config.MongoURI)
	var err error
	dbClient, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal("Connection failed:", err)
	}

	err = dbClient.Ping(ctx, nil)
	if err != nil {
		log.Fatal("Could not ping MongoDB:", err)
	}

	db = dbClient.Database("test")
	fmt.Println("Successfully connected to MongoDB!")

	mux := http.NewServeMux()
	mux.HandleFunc("/", PublicTimelineHandler)
	mux.HandleFunc("/add_message", AddMessageHandler)

	log.Fatal(http.ListenAndServe(":5000", AuthMiddleware(mux)))
}

func getUserID(username string) primitive.ObjectID {
	var result struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	filter := bson.M{"username": username}
	err := db.Collection("user").FindOne(ctx, filter).Decode(&result)
	if err != nil {
		return primitive.NilObjectID
	}
	return result.ID
}

func formatDatetime(timestamp int64) string {
	t := time.Unix(timestamp, 0).UTC()
	return t.Format("2006-01-02 @ 15:04")
}

func gravatarURL(email string, size int) string {
	cleanEmail := strings.ToLower(strings.TrimSpace(email))
	hash := md5.Sum([]byte(cleanEmail))
	hashString := hex.EncodeToString(hash[:])
	return fmt.Sprintf("http://www.gravatar.com/avatar/%s?d=identicon&s=%d", hashString, size)
}

// AuthMiddleware veryfie user
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "minitwit-session")
		if userIDStr, ok := session.Values["user_id"].(string); ok {
			fmt.Println("User ID found in session:", userIDStr)
			var currentUser User
			objID, _ := primitive.ObjectIDFromHex(userIDStr)

			err := db.Collection("user").FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&currentUser)

			if err == nil {
				ctx := context.WithValue(r.Context(), "user", currentUser)
				r = r.WithContext(ctx)
			}
		}

		next.ServeHTTP(w, r)
	})
}

func timeline(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user")
	if user != nil {
		u := user.(User)
		fmt.Fprintf(w, "Hello logged in user: %s", u.Username)
	} else {
		w.Write([]byte("Hello! You are not logged in. This is the public timeline."))
	}
}

func queryDatabaseForMessages(limit int) ([]TimelineMessage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := db.Collection("message")

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

	var messages []TimelineMessage

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

		messages = append(messages, TimelineMessage{
			Text:     result.Text,
			PubDate:  int(result.PubDate),
			Username: result.AuthorInfo.Username,
			Email:    result.AuthorInfo.Email,
		})
	}

	return messages, nil
}

func PublicTimelineHandler(w http.ResponseWriter, r *http.Request) {
	msgs, err := queryDatabaseForMessages(30)
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), 500)
		return
	}

	data := TimelinePage{
		BaseContext: BaseContext{
			User:    getCurrentUser(r),
			Flashes: getFlash(w, r),
		},
		Messages:  msgs,
		PageTitle: "Public Timeline",
		PageID:    "public_timeline",
	}

	funcMap := template.FuncMap{
		"gravatar":       func(email string) string { return gravatarURL(email, 48) },
		"datetimeformat": formatDatetime, // Mapping the function you already wrote
	}

	tmpl, err := template.New("layout.html").Funcs(funcMap).ParseFiles("templates/layout.html", "templates/timeline.html")

	if err != nil {
		http.Error(w, "Template Parse Error: "+err.Error(), 500)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Println("Template Execution Error:", err)
	}
}

func AddMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	userVal := r.Context().Value("user")
	if userVal == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	currentUser := userVal.(User)

	text := r.FormValue("text")

	if text != "" {
		collection := db.Collection("message")

		doc := bson.M{
			"author_id": currentUser.ID,
			"text":      text,
			"pub_date":  time.Now().Unix(),
			"flagged":   false,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := collection.InsertOne(ctx, doc)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			log.Println("Insert error:", err)
			return
		}

		setFlash(w, "Your message was recorded")
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func setFlash(w http.ResponseWriter, message string) {
	c := &http.Cookie{
		Name:  "flash",
		Value: base64.StdEncoding.EncodeToString([]byte(message)),
		Path:  "/",
	}
	http.SetCookie(w, c)
}

func getFlash(w http.ResponseWriter, r *http.Request) []string {
	c, err := r.Cookie("flash")
	if err != nil {
		return nil // No flash message
	}

	val, _ := base64.StdEncoding.DecodeString(c.Value)

	http.SetCookie(w, &http.Cookie{
		Name:    "flash",
		MaxAge:  -1,
		Expires: time.Unix(1, 0),
		Path:    "/",
	})

	return []string{string(val)}
}

func getCurrentUser(r *http.Request) *User {

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
