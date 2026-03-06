package app

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	. "minitwit/types"

	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// Global variables - exported for use by handlers

var (
	Config      Configuration
	DBClient    *mongo.Client
	DB          *mongo.Database // Specific handle to the "test" database
	Store       = sessions.NewCookieStore([]byte("development key"))
	ErrorCounts = make(map[string]int)
	ErrorLogs   []string
	LogMutex    sync.Mutex
)

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
func QueryDatabaseForMessages(limit int, skip int) ([]Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := DB.Collection("message")

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{{Key: "flagged", Value: false}}}},

		{{Key: "$sort", Value: bson.D{{Key: "pub_date", Value: -1}}}},

		{{Key: "$skip", Value: skip}},

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
func GetFollowedMessages(userID primitive.ObjectID, limit int, skip int) ([]Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Get the list of people I follow
	// We query the "follower" collection where who_id == my userID
	followerColl := DB.Collection("follower")
	cursor, err := followerColl.Find(ctx, bson.M{"who_id": userID})
	if err != nil {
		return nil, err
	}

	// We need a slice of ObjectIDs to pass to the $in query
	// Start with the user's OWN ID (so they see their own posts)
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

	// 2. Query Messages with Aggregation
	// Now we match messages where author_id is IN our list
	messageColl := DB.Collection("message")

	pipeline := mongo.Pipeline{
		// MATCH: Flagged is false AND author_id is in our list
		{{Key: "$match", Value: bson.D{
			{Key: "flagged", Value: false},
			{Key: "author_id", Value: bson.D{{Key: "$in", Value: followedIDs}}},
		}}},

		// SORT: Newest first
		{{Key: "$sort", Value: bson.D{{Key: "pub_date", Value: -1}}}},

		// SKIP
		{{Key: "$skip", Value: skip}},

		// LIMIT
		{{Key: "$limit", Value: limit}},

		// LOOKUP: Join with 'user' table to get Username/Email
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "user"},
			{Key: "localField", Value: "author_id"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "author_info"},
		}}},

		// UNWIND: Flatten the author_info array
		{{Key: "$unwind", Value: "$author_info"}},
	}

	// 3. Execute and Decode
	cursor, err = messageColl.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var messages []Message
	for cursor.Next(ctx) {
		// We decode into a temporary struct to handle the nested AuthorInfo
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

		// Map to your main Message struct
		messages = append(messages, Message{
			Text:     result.Text,
			PubDate:  int(result.PubDate),
			Username: result.AuthorInfo.Username,
			//Email:    result.AuthorInfo.Email, // Ensure your Message struct has this field
		})
	}

	return messages, nil
}

func LoadPreviousErrors() {
	// 1. Open the tracker file
	file, err := os.OpenFile("errors_tracker.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	LogMutex.Lock()
	defer LogMutex.Unlock()

	scanner := bufio.NewScanner(file) //read the file
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "- ") {
			// Your format is: "- <Error Message>: <Number> times"

			lastColonIdx := strings.LastIndex(line, ":") //LastIndex is parsing from the right side, it finds the number in the end of line
			if lastColonIdx == -1 {
				continue
			}

			msg := line[2:lastColonIdx]                        // Extract the message text (stripping the "- " from the front)
			numStr := strings.TrimSpace(line[lastColonIdx+1:]) // Extract the number (stripping the " times" from the end)
			numStr = strings.TrimSuffix(numStr, " times")

			count, err := strconv.Atoi(numStr) // Convert the text number back to an integer
			if err == nil {
				ErrorCounts[msg] = count
			}
		}
	}
}

func LogFollowError(errorMessage string) {
	LogMutex.Lock()
	defer LogMutex.Unlock()

	ErrorCounts[errorMessage]++
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	entry := fmt.Sprintf("[%s] %s", timestamp, errorMessage)
	ErrorLogs = append(ErrorLogs, entry)

	// --- FILE 1: THE PERMANENT LOG (Nothing is ever erased) ---
	// We use O_APPEND and NO O_TRUNC here
	fHistory, err := os.OpenFile("errors_history.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		fmt.Fprintln(fHistory, entry)
		fHistory.Close()
	}

	// --- FILE 2: THE DASHBOARD (Rewritten every time for easy reading) ---
	// We keep O_TRUNC here to keep the counters at the top
	fDash, err := os.OpenFile("errors_tracker.log", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return
	}
	defer fDash.Close()

	fmt.Fprintln(fDash, "=== LIVE SESSION SUMMARY ===")
	for msg, count := range ErrorCounts {
		fmt.Fprintf(fDash, "- %s: %d times\n", msg, count)
	}
}

func GetPageAndSkip(pageStr string) (int, int) {
	page := 1
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	// Calculate skip for pagination
	skip := (page - 1) * PER_PAGE
	return skip, page
}

func CalculateNextPage(totalMessages int64, page int) (int, int) {
	nextPage := -1
	if totalMessages > int64(page*PER_PAGE) {
		nextPage = page + 1
	}

	prevPage := -1
	if page > 1 {
		prevPage = page - 1
	}

	return nextPage, prevPage
}

// CountFollowedMessages counts the total messages from a user and those they follow
func CountFollowedMessages(userID primitive.ObjectID) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Get the list of people I follow
	followerColl := DB.Collection("follower")
	cursor, err := followerColl.Find(ctx, bson.M{"who_id": userID})
	if err != nil {
		return 0, err
	}

	// Start with the user's OWN ID
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

	// 2. Count the messages where author_id is IN our list
	filter := bson.M{
		"flagged":   false,
		"author_id": bson.M{"$in": followedIDs},
	}

	return DB.Collection("message").CountDocuments(ctx, filter)
}
