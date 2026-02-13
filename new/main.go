//commands to check functionality

//1. you can do docker composition
//docker-compose up --build
//docker composition is set for port 5001! -> http://localhost:5001

//2. do it manually but than don't do step 1
//start a temporary database
//docker run --name my-test-mongo -p 27017:27017 -d mongo:latest

//check if docker container is running
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
	"encoding/base64"
	"encoding/hex"
	"fmt"           // replace print() in python
	"html/template" // for rendering HTML templates
	"log"           // for error reporting
	"net/http"      // built-in library which replace flask
	"os"            // read environment variables (for example DB_IP)
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Configuration struct {
	Debug     bool
	SecretKey string
	MongoURI  string
}

type User struct {
	ID       primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Username string             `json:"username" bson:"username"`
	Email    string             `json:"email" bson:"email"`
	PW       string             `json:"pw" bson:"pw"`
	HashedPW string             `json:"hashedpw" bson:"hashedpw"`
}

type Message struct {
	ID        primitive.ObjectID `bson:"_id"`
	MessageID int              `bson:"message_id"`
	AuthorID  int              `bson:"author_id"`
	Text      string             `bson:"text"`
	PubDate   int              `bson:"pub_date"`
	Flagged   int                `bson:"flagged"`
	Username  string             `bson:"username"`
}

type BaseContext struct {
	User    *User    // Wraps the current user (replaces g.user)
	Flashes []string // Replaces get_flashed_messages()
}

type TimelinePage struct {
	BaseContext // Embeds User and Flashes automatically
	Messages    []Message
	ProfileUser *User
	PageTitle   string // Needed for {{ .PageTitle }}
	PageID      string // Needed for "active" tab logic (public vs user)
}
type TimelineUserData struct {
	PageTitle   string // Replaces self.title() logic
	PageID      string // Replaces request.endpoint logic ("public", "user", "personal")
	Messages    []Message
	ProfileUser *User // Can be nil if not on a user profile
	CurrentUser *User // Represents g.user
	IsFollowing bool  // Replaces 'followed' boolean
	Flashes     []interface{}
}

// global variables
var config Configuration
var dbClient *mongo.Client
var db *mongo.Database // Specific handle to the "test" database
var store = sessions.NewCookieStore([]byte("development key"))

const PER_PAGE = 30 // Same as Python version

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

	ResolveClientDB()

	router := mux.NewRouter()
	router.Use(beforeAfterMiddleware)
	router.Use(AuthMiddleware)

	// Serve static files
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	router.HandleFunc("/", PublicTimelineHandler).Methods("GET")
	router.HandleFunc("/register", RegisterHandler)
	router.HandleFunc("/login", LoginHandler)
	router.HandleFunc("/logout", LogoutHandler)
	router.HandleFunc("/{username}", userTimeline).Methods("GET")
	router.HandleFunc("/{username}/follow", followUser).Methods("GET")
	router.HandleFunc("/{username}/unfollow", unfollowUser).Methods("GET")
	router.HandleFunc("/add_message", AddMessageHandler).Methods("POST")
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

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	user := r.Context().Value("user")
	if user != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	errMsg := ""
	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		password2 := r.FormValue("password2")

		if username == "" {
			errMsg = "You have to enter a username"
		} else if email == "" || !strings.Contains(email, "@") {
			errMsg = "You have to enter a valid email address"
		} else if password == "" {
			errMsg = "You have to enter a password"
		} else if password != password2 {
			errMsg = "The two passwords do not match"
		} else if getUserID(username) != primitive.NilObjectID {
			errMsg = "The username is already taken"
		} else {
			newUser := User{
				Username: username,
				Email:    email,
				PW:       password,
				HashedPW: password,
			}
			db.Collection("user").InsertOne(ctx, newUser)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
	}

	if errMsg != "" {
		log.Println("Registration error:", errMsg)
	}
	RenderTemplate(w, "register.html", nil)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	user := r.Context().Value("user")
	if user != nil {
		// User is already logged in, redirect to timeline
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		var foundUser User
		filter := bson.M{"username": username}

		dberr := db.Collection("user").FindOne(ctx, filter).Decode(&foundUser)
		if dberr != nil {
			if dberr == mongo.ErrNoDocuments {
				log.Println("User not found:", username)
			} else {
				log.Println("Database error:", dberr)
			}
		} else {
			if !checkPasswordHash(password, foundUser.HashedPW) {
				log.Println("Password doesn't match")
			} else {
				session, _ := store.Get(r, "minitwit-session")
				session.Values["user_id"] = foundUser.ID.Hex()
				session.Save(r, w)
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}
	}

	RenderTemplate(w, "login.html", nil)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "minitwit-session")
	session.AddFlash("You were logged out")
	for k := range session.Values {
		delete(session.Values, k)
	}
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func beforeAfterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Executing before request logic")
		ctx := context.WithValue(r.Context(), "user", nil)
		r = r.WithContext(ctx)

		// Call the next handler in the chain
		next.ServeHTTP(w, r)

		fmt.Println("Executing after request logic")
	})
}

func ResolveClientDB() *mongo.Client {
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
	return dbClient
}

func CloseClientDB() {
	if dbClient == nil {
		return
	}

	err := dbClient.Disconnect(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connection to MongoDB closed.")
}

func checkPasswordHash(password, hashedPW string) bool {
	// TODO: implement proper password hashing comparison
	return password == hashedPW
}

func RenderTemplate(w http.ResponseWriter, html string, data interface{}) {
	parsedTemplate, err := template.ParseFiles("./templates/" + html)
	if err != nil {
		log.Printf("Error loading template %s: %v", html, err)
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}
	err = parsedTemplate.Execute(w, data)
	if err != nil {
		log.Printf("Error executing template %s: %v", html, err)
		http.Error(w, "Template error", http.StatusInternalServerError)
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
		http.Error(w, "User not found", http.StatusNotFound) // abort(404)
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
			"who_id":  user.ID,
			"whom_id": profileUser.ID,
		}).Decode(&result)
		followed = (err == nil) // is not None
	}

	// Query: select message.*, user.* from message, user where
	//        user.user_id = message.author_id and user.user_id = ?
	//        order by message.pub_date desc limit ?
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opts := options.Find().SetSort(bson.M{"pub_date": -1}).SetLimit(PER_PAGE)
	cursor, _ := db.Collection("message").Find(ctx, bson.M{
		"author_id": profileUser.ID,
		"flagged":   0,
	}, opts)
	var messages []Message
	cursor.All(ctx, &messages)

	// Retrieve flash messages from session
	session, _ := store.Get(r, "minitwit-session")
	flashes := session.Flashes()
	session.Save(r, w)

	data := TimelineUserData{
		Messages:    messages,
		IsFollowing: followed,
		ProfileUser: &profileUser,
		CurrentUser: currentUser,
		Flashes:     []interface{},
	}
	RenderTemplate(w, "timeline.html", data)
}

func followUser(w http.ResponseWriter, r *http.Request) {
	// if not g.user: abort(401)
	currentUser := r.Context().Value("user")
	if currentUser == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized) // abort(401)
		return
	}
	user := currentUser.(User)
	username := mux.Vars(r)["username"]

	// whom_id = get_user_id(username)
	var result struct {
		ID int64 `bson:"user_id"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := db.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&result)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound) // if whom_id is None: abort(404)
		return
	}
	whomID := result.ID

	// g.db.execute('insert into follower (who_id, whom_id) values (?, ?)', [session['user_id'], whom_id])
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db.Collection("follower").InsertOne(ctx, bson.M{
		"who_id":  user.ID,
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
		http.Error(w, "Unauthorized", http.StatusUnauthorized) // abort(401)
		return
	}
	user := currentUser.(User)
	username := mux.Vars(r)["username"]

	// whom_id = get_user_id(username)
	var result struct {
		ID int64 `bson:"user_id"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := db.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&result)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound) // if whom_id is None: abort(404)
		return
	}
	whomID := result.ID

	// g.db.execute('delete from follower where who_id=? and whom_id=?', [session['user_id'], whom_id])
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db.Collection("follower").DeleteOne(ctx, bson.M{
		"who_id":  user.ID,
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

func queryDatabaseForMessages(limit int) ([]Message, error) {
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

func PublicTimelineHandler(w http.ResponseWriter, r *http.Request) {
	msgs, err := queryDatabaseForMessages(PER_PAGE)
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

	//funcMap := template.FuncMap{
	//	"gravatar":       func(email string) string { return gravatarURL(email, 48) },
	//	"datetimeformat": formatDatetime, // Mapping the function you already wrote
	//}

	RenderTemplate(w, "layout.html", data)
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
