//commands to check functionality

//1. you can do docker composition
//docker-compose up --build
//docker composition is set for port 8080! -> http://localhost:8080

//2. do it manually but than don't do step 1
//start a temporary database
//docker run --name my-test-mongo -p 27017:27017 -d mongo:latest

//check if docker container is running
//docker ps
//if not, than start it
//docker start my-test-mongo

//download valid dependencies
//go mod tidy

// check if it works
// go run main.go
package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"           // replace print() in python
	"html/template" // for rendering HTML templates
	"log"           // for error reporting
	"minitwit/api"
	"net/http" // built-in library which replace flask
	"os"       // read environment variables (for example DB_IP)
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	MessageID int                `bson:"message_id"`
	AuthorID  int                `bson:"author_id"`
	Text      string             `bson:"text"`
	PubDate   int                `bson:"pub_date"`
	Flagged   int                `bson:"flagged"`
	Username  string             `bson:"username"`
}

type BaseContext struct {
	User    *User    // Wraps the current user (replaces g.user)
	Flashes []string // Replaces get_flashed_messages()
}

type TimelineUserData struct {
	PageTitle   string
	PageID      string // "public", "timeline", or "user"
	Messages    []Message
	ProfileUser *User // The user whose profile we are viewing (can be nil)
	CurrentUser *User // The user currently logged in (can be nil)
	IsFollowing bool
	Flashes     []string
	Page        int // Current page number
	NextPage    int // Next page number (-1 if no next)
	PrevPage    int // Previous page number (-1 if no prev)
}

// global variables
var (
	config      Configuration
	dbClient    *mongo.Client
	db          *mongo.Database // Specific handle to the "test" database
	store       = sessions.NewCookieStore([]byte("development key"))
	errorCounts = make(map[string]int)
	errorLogs   []string
	logMutex    sync.Mutex
)

const PER_PAGE = 30 // Same as Python version

var funcMap = template.FuncMap{
	"gravatar": func(email string) string {
		return gravatarURL(email)
	},
	"formatDate": func(timestamp int) string {
		return formatDatetime(int64(timestamp))
	},
}

func main() {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	ResolveClientDB()
	loadPreviousErrors() // if we would rerun our app, we want to load dictionary with our error values to our program memory

	// 1. Load Configuration & Connect to DB
	config = Configuration{
		Debug:     true,
		SecretKey: "development key",
	}
	if envKey := os.Getenv("SECRET_KEY"); envKey != "" {
		config.SecretKey = envKey
	}

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days (in seconds)
		HttpOnly: true,
		Secure:   false, // Setting to false for DigitalOcean because of HTTP and not HTTPS.
	}

	// 2. Create the main router
	router := mux.NewRouter()
	router.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	// Serve static files on the main router
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// ==========================================
	// 3. API ROUTES (Simulator)
	// ==========================================
	// Initialize your new API handler from the 'api' package
	apiHandler := api.NewAPI(db)

	router.HandleFunc("/latest", apiHandler.GetLatestHandler).Methods("GET")

	// The "Headers" matcher ensures JSON requests go to the API, not UI
	router.HandleFunc("/register", apiHandler.RegisterHandler).Methods("POST").Headers("Content-Type", "application/json")

	// Wrapping the protected API endpoints with the API's specific Basic Auth middleware
	router.HandleFunc("/msgs", apiHandler.AuthMiddleware(apiHandler.GetMessagesHandler)).Methods("GET")
	router.HandleFunc("/msgs/{username}", apiHandler.AuthMiddleware(apiHandler.UserMessagesHandler)).Methods("GET", "POST")
	router.HandleFunc("/fllws/{username}", apiHandler.AuthMiddleware(apiHandler.FollowsHandler)).Methods("GET", "POST")

	// ==========================================
	// 4. UI ROUTES (Web Browser)
	// ==========================================
	// Creating a subrouter specifically for the UI pages
	uiRouter := router.PathPrefix("/").Subrouter()

	// Apply your UI session/cookie middleware ONLY to the UI routes
	uiRouter.Use(beforeAfterMiddleware)
	uiRouter.Use(AuthMiddleware)

	// Original routes
	uiRouter.HandleFunc("/", PublicTimelineHandler).Methods("GET")
	uiRouter.HandleFunc("/timeline", PersonalTimelineHandler).Methods("GET")
	uiRouter.HandleFunc("/register", RegisterHandler) // Matches standard form submissions
	uiRouter.HandleFunc("/login", LoginHandler)
	uiRouter.HandleFunc("/logout", LogoutHandler)
	uiRouter.HandleFunc("/user/follow/{username}", followUser).Methods("GET")
	uiRouter.HandleFunc("/user/unfollow/{username}", unfollowUser).Methods("GET")
	uiRouter.HandleFunc("/user/{username}", UserTimelineHandler).Methods("GET")
	uiRouter.HandleFunc("/add_message", AddMessageHandler).Methods("POST")
	fmt.Println("Server running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func loadPreviousErrors() {
	// 1. Open the tracker file
	file, err := os.OpenFile("errors_tracker.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	logMutex.Lock()
	defer logMutex.Unlock()

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
				errorCounts[msg] = count
			}
		}
	}
}

func logFollowError(errorMessage string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	errorCounts[errorMessage]++
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	entry := fmt.Sprintf("[%s] %s", timestamp, errorMessage)
	errorLogs = append(errorLogs, entry)

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
	for msg, count := range errorCounts {
		fmt.Fprintf(fDash, "- %s: %d times\n", msg, count)
	}
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
	timezone, err := time.LoadLocation("Europe/Warsaw")

	if err != nil {
		// Logging the error so we can see it in 'docker logs' if it ever breaks
		log.Printf("Warning: Could not load Warsaw timezone, falling back to UTC: %v", err)
		timezone = time.UTC
	}

	t := time.Unix(timestamp, 0).In(timezone)
	return t.Format("2006-01-02 @ 15:04")
}

func gravatarURL(email string) string {
	cleanEmail := strings.ToLower(strings.TrimSpace(email))
	//we create hash because thats how website request data
	hash := md5.Sum([]byte(cleanEmail))
	//Convert the hash (binary) into a Hex String (text)
	hashString := hex.EncodeToString(hash[:])
	return fmt.Sprintf("http://www.gravatar.com/avatar/%s?d=identicon&s=%d", hashString, 80)
}

// AuthMiddleware verify user
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
			} else {
				// TUTAJ JEST ROZWIĄZANIE TWOJEGO PROBLEMU:
				if err == context.DeadlineExceeded {
					logFollowError("DB Timeout: AuthMiddleware could not connect to DB in 5s")
				} else if err != mongo.ErrNoDocuments {
					logFollowError("DB Error: AuthMiddleware crashed while verifying session")
				}
			}
		}

		// 5. Pass the request to the next handler
		next.ServeHTTP(w, r)
	})
}

// RegisterHandler manages user sign-ups by validating form data and saving new users to the DB.
// It prevents logged-in users from re-registering and handles error reporting via the UI.
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	user := r.Context().Value("user")
	if user != nil {
		setFlash(w, "You are already logged in as "+user.(User).Username)
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

	data := TimelineUserData{
		PageTitle: "Register",
		Flashes:   []string{},
	}

	if errMsg != "" {
		log.Println("Registration error:", errMsg)
		data.Flashes = append(data.Flashes, errMsg)
	}
	RenderTemplate(w, "register.html", data)
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

	var flashes []string

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
				flashes = append(flashes, "Invalid username")
			} else {
				flashes = append(flashes, "Database error occurred")
				log.Println("Database error:", dberr)
			}
		} else {
			if !checkPasswordHash(password, foundUser.HashedPW) {
				log.Println("Password doesn't match")
				flashes = append(flashes, "Invalid password")
			} else {
				session, _ := store.Get(r, "minitwit-session")
				session.Values["user_id"] = foundUser.ID.Hex()
				session.Save(r, w)
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}
	}

	data := TimelineUserData{
		PageTitle: "Sign In",
		Flashes:   flashes,
	}

	RenderTemplate(w, "login.html", data)
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

func RenderTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
	// 1. Attach Funcs BEFORE parsing
	t := template.New("base").Funcs(funcMap)

	// 2. Parse Layout + Page
	t, err := t.ParseFiles("templates/layout.html", "templates/"+tmplName)
	if err != nil {
		log.Println("Parse Error:", err)
		http.Error(w, "Internal Error", 500)
		return
	}

	// 3. Execute "base"
	err = t.ExecuteTemplate(w, "base", data)
	if err != nil {
		log.Println("Exec Error:", err)
		http.Error(w, "Internal Error", 500)
	}
}

func UserTimelineHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	skip, page := getPageAndSkip(r.URL.Query().Get("page"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Find the Profile User
	var profileUser User
	err := db.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 2. Get Current User (if any)
	var currUser *User
	if u := r.Context().Value("user"); u != nil {
		val := u.(User)
		currUser = &val
	}

	// 3. Check "Following" status
	followed := false
	if currUser != nil {
		var result struct{}
		err := db.Collection("follower").FindOne(ctx, bson.M{
			"who_id":  currUser.ID,
			"whom_id": profileUser.ID,
		}).Decode(&result)
		if err == nil {
			followed = true
		}
	}

	filter := bson.M{
		"author_id": profileUser.ID,
		"flagged":   false,
	}
	// 4. Get Messages & Fill Missing Data
	opts := options.Find().SetSort(bson.D{{Key: "pub_date", Value: -1}, {Key: "_id", Value: -1}}).SetSkip(int64(skip)).SetLimit(int64(PER_PAGE))

	totalMessages, _ := db.Collection("message").CountDocuments(ctx, filter)

	cursor, err := db.Collection("message").Find(ctx, bson.M{
		"author_id": profileUser.ID,
		"flagged":   false,
	}, opts)

	var messages []Message

	if err == nil {
		// A. Define a temporary struct that matches MongoDB types EXACTLY
		var rawResults []struct {
			Text     string             `bson:"text"`
			PubDate  int64              `bson:"pub_date"`  // DB uses int64
			AuthorID primitive.ObjectID `bson:"author_id"` // DB uses ObjectID
			Flagged  bool               `bson:"flagged"`   // DB uses bool
		}

		// B. Decode into this safe struct first
		// If this fails, we will now see the error!
		if err := cursor.All(ctx, &rawResults); err != nil {
			fmt.Println("Decoding error:", err) // Check your terminal if empty!
		}

		// C. Manually map to your view struct (just like PublicTimeline)
		for _, raw := range rawResults {
			msg := Message{
				Text:     raw.Text,
				PubDate:  int(raw.PubDate), // Convert int64 -> int
				Username: profileUser.Username,
				//Email:    profileUser.Email,
			}
			messages = append(messages, msg)
		}
	}

	// 5. Determine next/prev pages
	nextPage, prevPage := calculateNextPage(totalMessages, page)

	// 6. Render
	data := TimelineUserData{
		PageTitle:   profileUser.Username + "'s Timeline",
		PageID:      "user",
		Messages:    messages,
		ProfileUser: &profileUser,
		CurrentUser: currUser,
		IsFollowing: followed,
		Flashes:     getFlash(w, r),
		Page:        page,
		NextPage:    nextPage,
		PrevPage:    prevPage,
	}

	RenderTemplate(w, "timeline.html", data)
}

func followUser(w http.ResponseWriter, r *http.Request) {
	currentUser := r.Context().Value("user")
	if currentUser == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized) // abort(401)
		logFollowError("Unauthorized user (user not found) tried to follow another user or DB problem")
		return
	}
	user := currentUser.(User)
	username := mux.Vars(r)["username"]
	log.Println("we reded username: " + username)

	// whom_id = get_user_id(username)
	var profileUser User
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := db.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		if err == context.DeadlineExceeded {
			logFollowError("DB Timeout: FindOne took more than 5s for user")
		} else {
			logFollowError("Not found: we couldnt follow some user because he/she doesnt exsit")
		}
		return
	}

	if user.ID == profileUser.ID {
		logFollowError("Logic Error: User (Some user) tried to follow themselves")
		http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
		return
	}

	whomID := profileUser.ID
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, insertErr := db.Collection("follower").InsertOne(ctx, bson.M{
		"who_id":  user.ID,
		"whom_id": whomID,
	})
	if insertErr != nil {
		logFollowError("DB Error: InsertOne failed for following (some user)")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// g.db.commit() - MongoDB auto-commits
	session, cookies_error := store.Get(r, "minitwit-session")
	if cookies_error != nil {
		logFollowError("error on cookies (flash)")
	} else {
		session.AddFlash("You are now following \"" + username + "\"")
		session.Save(r, w)
	}
	http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
}

func unfollowUser(w http.ResponseWriter, r *http.Request) {
	// 1. Auth Check
	currentUser := r.Context().Value("user")
	if currentUser == nil {
		logFollowError("Unauthorized: Someone tried to unfollow without login")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user := currentUser.(User)
	username := mux.Vars(r)["username"]

	// 2. Find the user to unfollow
	var profileUser User
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel() // Ensures the timer is stopped when function returns

	err := db.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		if err == context.DeadlineExceeded {
			logFollowError("DB Timeout: FindOne took more than 5s for user (some user)")
		} else {
			logFollowError("Not Found: Could not unfollow (some user) because they do not exist")
		}
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 3. Delete the relationship
	// Re-initializing context/cancel for the second DB operation
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, deleteErr := db.Collection("follower").DeleteOne(ctx, bson.M{
		"who_id":  user.ID,
		"whom_id": profileUser.ID,
	})

	if deleteErr != nil {
		logFollowError("DB Error: DeleteOne failed for unfollowing " + username)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return // Prevents redirecting if the deletion failed
	}

	// 4. Handle Flash Messages and Redirect
	session, cookies_error := store.Get(r, "minitwit-session")
	if cookies_error != nil {
		logFollowError("Session Error: Failed to get session for unfollow flash")
	} else {
		session.AddFlash("You are no longer following \"" + username + "\"")
		session.Save(r, w)
	}

	http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
}

func queryDatabaseForMessages(limit int, skip int) ([]Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := db.Collection("message")

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

func getFollowedMessages(userID primitive.ObjectID, limit int, skip int) ([]Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Get the list of people I follow
	// We query the "follower" collection where who_id == my userID
	followerColl := db.Collection("follower")
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
	messageColl := db.Collection("message")

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

func PersonalTimelineHandler(w http.ResponseWriter, r *http.Request) {
	// Get page parameter from query string
	skip, page := getPageAndSkip(r.URL.Query().Get("page"))

	// 1. Get Current User (Security check)
	var currUser *User
	if u := r.Context().Value("user"); u != nil {
		val := u.(User)
		currUser = &val
	}

	if currUser == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// 2. Logic: Get messages from user AND people they follow
	// (You likely have a DB function for this, e.g., getFollowedMessages)
	msgs, err := getFollowedMessages(currUser.ID, PER_PAGE, skip)
	if err != nil {
		log.Printf("error fetching followed messages for user %s: %v", currUser.ID.Hex(), err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	filter := bson.M{
		"author_id": currUser.ID,
		"flagged":   false,
	}

	totalMessages, _ := db.Collection("message").CountDocuments(ctx, filter)
	// 3. Determine next/prev pages
	nextPage, prevPage := calculateNextPage(totalMessages, page)

	// 4. Render
	data := TimelineUserData{
		PageTitle:   "My Timeline",
		PageID:      "personal", // <--- CRITICAL: Triggers the Input Box in HTML
		Messages:    msgs,
		CurrentUser: currUser,
		ProfileUser: currUser,
		Page:        page,
		NextPage:    nextPage,
		PrevPage:    prevPage,
	}

	RenderTemplate(w, "timeline.html", data)
}

func PublicTimelineHandler(w http.ResponseWriter, r *http.Request) {
	// Get page parameter from query string
	skip, page := getPageAndSkip(r.URL.Query().Get("page"))

	// 1. Get Messages
	// (Assuming queryDatabaseForMessages returns []Message)
	msgs, err := queryDatabaseForMessages(PER_PAGE, skip)
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), 500)
		return
	}

	// 2. Get Current User (if logged in)
	var currUser *User
	if u := r.Context().Value("user"); u != nil {
		val := u.(User) // Cast interface{} to User struct
		currUser = &val
	}

	// 3. Determine next/prev pages
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	filter := bson.M{
		"author_id": currUser.ID,
		"flagged":   false,
	}
	totalMessages, _ := db.Collection("message").CountDocuments(ctx, filter)
	nextPage, prevPage := calculateNextPage(totalMessages, page)

	// 4. Setup Data
	data := TimelineUserData{
		PageTitle:   "Public Timeline",
		PageID:      "public", // Matches {{if eq .PageID "public"}} in template
		Messages:    msgs,
		CurrentUser: currUser,
		ProfileUser: nil,            // Not viewing a specific profile
		Flashes:     getFlash(w, r), // Your flash helper
		Page:        page,
		NextPage:    nextPage,
		PrevPage:    prevPage,
	}

	RenderTemplate(w, "timeline.html", data)
}

func AddMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	userVal := r.Context().Value("user")
	if userVal == nil {
		logFollowError("POST ERROR: Unauthorized user tried to create a post")
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
			if err == context.DeadlineExceeded {
				logFollowError("POST DB TIMEOUT: Message creation took >5s for user " + currentUser.Username)
			} else {
				logFollowError("POST DB ERROR: Failed to insert message for " + currentUser.Username + ": " + err.Error())
			}
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

func getPageAndSkip(pageStr string) (int, int) {
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

func calculateNextPage(totalMessages int64, page int) (int, int) {
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
