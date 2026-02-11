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
	"log"      // for error reporting
	"net/http" // built-in library which replace flask
	"os"       // read environment variables (for example DB_IP)
	"strings"
	"text/template"
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
	ID       primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Username string             `json:"username" bson:"username"`
	Email    string             `json:"email" bson:"email"`
	PW       string             `json:"pw" bson:"pw"`
	HashedPW string             `json:"hashedpw" bson:"hashedpw"`
}

// global variables
var config Configuration
var dbClient *mongo.Client
var db *mongo.Database // Specific handle to the "test" database
var store = sessions.NewCookieStore([]byte("development key"))

func main() {
	// init routes
	r := mux.NewRouter()
	r.Use(beforeAfterMiddleware)
	r.Use(AuthMiddleware)

	// Serve static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	r.HandleFunc("/", TimelineHandler)
	r.HandleFunc("/register", RegisterHandler)
	r.HandleFunc("/login", LoginHandler)
	r.HandleFunc("/logout", LogoutHandler)

	// r.HandleFunc("/add_message")
	// r.HandleFunc("/{username}/unfollow")
	// r.HandleFunc("/{username}/follow")
	// r.HandleFunc("/{username}")
	// r.HandleFunc("/public")
	config = Configuration{
		Debug:     true,              // Default: DEBUG=True
		SecretKey: "development key", // Default: SECRET_KEY='development key'
		// for now MongoURI is Zero Value, we will overwrite it later
	}

	// Override from Environment (Like app.config.from_envvar)
	if envKey := os.Getenv("SECRET_KEY"); envKey != "" {
		config.SecretKey = envKey
	}

	// Initialize database connection at startup
	ResolveClientDB()

	// Load Configuration
	log.Fatal(http.ListenAndServe(":5000", r))
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

func TimelineHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user") //we checked if visitor has valus of user
	if user != nil {
		RenderTemplate(w, "timeline.html")
	} else {
		RenderTemplate(w, "layout.html")
	}
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
	RenderTemplate(w, "register.html")
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

	RenderTemplate(w, "login.html")
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

func RenderTemplate(w http.ResponseWriter, html string) {
	parsedTemplate, err := template.ParseFiles("./templates/" + html)
	if err != nil {
		log.Printf("Error loading template %s: %v", html, err)
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}
	err = parsedTemplate.Execute(w, nil)
	if err != nil {
		log.Printf("Error executing template %s: %v", html, err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}
