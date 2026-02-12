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
	"context" // needed for the timeout logic
	"crypto/md5"
	"encoding/hex"
	"fmt"      // replace print() in python
	"html/template" // for rendering HTML templates
	"log"      // for error reporting
	"net/http" // built-in library which replace flask
	"os"       // read environment variables (for example DB_IP)
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

type Configuration struct {
	Debug     bool
	SecretKey string
	MongoURI  string
}

type User struct {
	ID       primitive.ObjectID `bson:"_id"`
	UserID   int64              `bson:"user_id"`
	Username string             `bson:"username"`
	Email    string             `bson:"email"`
	PWHash   string             `bson:"pw_hash"`
}

type Message struct {
	ID        primitive.ObjectID `bson:"_id"`
	MessageID int64              `bson:"message_id"`
	AuthorID  int64              `bson:"author_id"`
	Text      string             `bson:"text"`
	PubDate   int64              `bson:"pub_date"`
	Flagged   int                `bson:"flagged"`
}

// global variables
var config Configuration
var dbClient *mongo.Client
var db *mongo.Database // Specific handle to the "test" database
var store = sessions.NewCookieStore([]byte("development key"))

const PER_PAGE = 30  // Same as Python version

func main() {
	// Load Configuration
	config = Configuration{
		Debug:     true,              // Default: DEBUG=True
		SecretKey: "development key", // Default: SECRET_KEY='development key'
		// for now MongoURI is Zero Value, we will overwrite it later
	}

	// Override from Environment (Like app.config.from_envvar)
	if envKey := os.Getenv("SECRET_KEY"); envKey != "" {
		config.SecretKey = envKey
	}

	// Setup Database URI (Replaces db_ip = os.getenv / app.config["MONGO_URI"])
	dbIP := os.Getenv("DB_IP")
	if dbIP == "" {
		dbIP = "localhost" // Fallback if running outside Docker
	}
	config.MongoURI = fmt.Sprintf("mongodb://%s:27017", dbIP)

	// Connect to MongoDB (Replaces mongo = PyMongo(app))
	fmt.Println("Connecting to:", config.MongoURI)

	// Create a context with a 10-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect
	clientOptions := options.Client().ApplyURI(config.MongoURI)
	var err error
	dbClient, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal("Connection failed:", err)
	}

	// Ping to verify
	err = dbClient.Ping(ctx, nil)
	if err != nil {
		log.Fatal("Could not ping MongoDB:", err)
	}

	db = dbClient.Database("test")
	fmt.Println("Successfully connected to MongoDB!")
	fmt.Printf("Loaded Config: Debug=%v, SecretKey=%s\n", config.Debug, config.SecretKey)

	router := mux.NewRouter()
	router.HandleFunc("/", timeline).Methods("GET")
	router.HandleFunc("/{username}", userTimeline).Methods("GET")
	router.HandleFunc("/{username}/follow", followUser).Methods("GET")
	router.HandleFunc("/{username}/unfollow", unfollowUser).Methods("GET")

	log.Fatal(http.ListenAndServe(":5000", AuthMiddleware(router)))
}

func getUserID(username string) primitive.ObjectID {
	// Create a variable to hold the answer
	var result struct {
		ID primitive.ObjectID `bson:"_id"` //it force ID to be 12 bytes of hex data
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Search the "user" collection
	filter := bson.M{"username": username}
	// we fill result (on the end in right), if we will have error it is assign on the left side
	err := db.Collection("user").FindOne(ctx, filter).Decode(&result)
	// Check if assign operation thrown an error
	if err != nil {
		return primitive.NilObjectID
	}
	return result.ID
}

// time stemp means how many seconds passed since january 1st,1970
func formatDatetime(timestamp int64) string {
	t := time.Unix(timestamp, 0).UTC() //(0 means zero nanoseconds)
	return t.Format("2006-01-02 @ 15:04")
}

func gravatarURL(email string, size int) string {
	cleanEmail := strings.ToLower(strings.TrimSpace(email))
	//we create hash because thats how website request data
	hash := md5.Sum([]byte(cleanEmail))
	//Convert the hash (binary) into a Hex String (text)
	hashString := hex.EncodeToString(hash[:])
	return fmt.Sprintf("http://www.gravatar.com/avatar/%s?d=identicon&s=%d", hashString, size)
}

// AuthMiddleware veryfie user
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { //its anonymus function
		session, _ := store.Get(r, "minitwit-session") //Get the Session (Cookie)

		// 2. Check if "user_id" exists in the session
		if userIDStr, ok := session.Values["user_id"].(string); ok {
			fmt.Println("User ID found in session:", userIDStr)
			// 3. Find the User in DB
			var currentUser User
			objID, _ := primitive.ObjectIDFromHex(userIDStr)

			err := db.Collection("user").FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&currentUser)

			if err == nil {
				ctx := context.WithValue(r.Context(), "user", currentUser) // we create updated context
				r = r.WithContext(ctx)                                     // update the request with the new context
			}
		}

		// 5. Pass the request to the next handler
		next.ServeHTTP(w, r)
	})
}

func timeline(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user") //we checked if visitor has valus of user
	if user != nil {
		u := user.(User)
		fmt.Fprintf(w, "Hello logged in user: %s", u.Username)
	} else {
		w.Write([]byte("Hello! You are not logged in. This is the public timeline."))
	}
}

func userTimeline(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	
	// Query: select * from user where username = ? (one=True)
	var profileUser User
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := db.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)  // abort(404)
		return
	}
	
	// followed = False
	followed := false
	// if g.user:
	if currentUser := r.Context().Value("user"); currentUser != nil {
		user := currentUser.(User)
		// Query: select 1 from follower where who_id = ? and whom_id = ? (one=True)
		var result struct{}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := db.Collection("follower").FindOne(ctx, bson.M{
			"who_id":  user.UserID,
			"whom_id": profileUser.UserID,
		}).Decode(&result)
		followed = (err == nil)  // is not None
	}
	
	// Query: select message.*, user.* from message, user where
	//        user.user_id = message.author_id and user.user_id = ?
	//        order by message.pub_date desc limit ?
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opts := options.Find().SetSort(bson.M{"pub_date": -1}).SetLimit(PER_PAGE)
	cursor, _ := db.Collection("message").Find(ctx, bson.M{
		"author_id": profileUser.UserID,
		"flagged":   0,
	}, opts)
	var messages []Message
	cursor.All(ctx, &messages)
	
	// Retrieve flash messages from session
	session, _ := store.Get(r, "minitwit-session")
	flashes := session.Flashes()
	session.Save(r, w)
	
	// return render_template('timeline.html', messages=..., followed=..., profile_user=...)
	tmpl, err := template.ParseFiles("templates/timeline.html")
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, map[string]interface{}{
		"messages":     messages,
		"followed":     followed,
		"profile_user": profileUser,
		"user":         r.Context().Value("user"),
		"flashes":      flashes,
	})
}

func followUser(w http.ResponseWriter, r *http.Request) {
	// if not g.user: abort(401)
	currentUser := r.Context().Value("user")
	if currentUser == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)  // abort(401)
		return
	}
	user := currentUser.(User)
	username := mux.Vars(r)["username"]
	
	// whom_id = get_user_id(username)
	var result struct {
		UserID int64 `bson:"user_id"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := db.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&result)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)  // if whom_id is None: abort(404)
		return
	}
	whomID := result.UserID
	
	// g.db.execute('insert into follower (who_id, whom_id) values (?, ?)', [session['user_id'], whom_id])
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db.Collection("follower").InsertOne(ctx, bson.M{
		"who_id":  user.UserID,
		"whom_id": whomID,
	})
	// g.db.commit() - MongoDB auto-commits
	
	// flash('You are now following "%s"' % username)
	session, _ := store.Get(r, "minitwit-session")
	session.AddFlash("You are now following \"" + username + "\"")
	session.Save(r, w)
	
	// return redirect(url_for('user_timeline', username=username))
	http.Redirect(w, r, "/"+username, http.StatusSeeOther)
}

func unfollowUser(w http.ResponseWriter, r *http.Request) {
	// if not g.user: abort(401)
	currentUser := r.Context().Value("user")
	if currentUser == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)  // abort(401)
		return
	}
	user := currentUser.(User)
	username := mux.Vars(r)["username"]
	
	// whom_id = get_user_id(username)
	var result struct {
		UserID int64 `bson:"user_id"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := db.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&result)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)  // if whom_id is None: abort(404)
		return
	}
	whomID := result.UserID
	
	// g.db.execute('delete from follower where who_id=? and whom_id=?', [session['user_id'], whom_id])
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db.Collection("follower").DeleteOne(ctx, bson.M{
		"who_id":  user.UserID,
		"whom_id": whomID,
	})
	// g.db.commit() - MongoDB auto-commits
	
	// flash('You are no longer following "%s"' % username)
	session, _ := store.Get(r, "minitwit-session")
	session.AddFlash("You are no longer following \"" + username + "\"")
	session.Save(r, w)
	
	// return redirect(url_for('user_timeline', username=username))
	http.Redirect(w, r, "/"+username, http.StatusSeeOther)
}
