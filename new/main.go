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
	"fmt" // replace print() in python
	"minitwit/api"
	"minitwit/handlers"
	"net/http" // built-in library which replace flask
	"os"       // read environment variables (for example DB_IP)
	_ "time/tzdata"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

import (
	"minitwit/app"
	. "minitwit/db_setup"
	. "minitwit/middleware"
	. "minitwit/types"
)

func main() {
	app.LoadPreviousErrors()
	// Load Configuration
	app.Config = Configuration{
		Debug:     true,
		SecretKey: "development key",
	}
	// Override from Environment
	if envKey := os.Getenv("SECRET_KEY"); envKey != "" {
		app.Config.SecretKey = envKey
	}
	app.Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days (in seconds)
		HttpOnly: true,
		Secure:   false, // Setting to false for DigitalOcean because of HTTP and not HTTPS.
	}
	app.DBClient, app.DB = ResolveClientDB(app.Config)
	authMiddleware := AuthMiddleware(app.Store, app.DB)

	router := mux.NewRouter()
	router.Use(BeforeAfterMiddleware)
	router.Use(authMiddleware)

	// Serve static files
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// ==========================================
	// 3. API ROUTES (Simulator)
	// ==========================================
	// Initialize your new API handler from the 'api' package
	apiHandler := api.NewAPI(app.DB)

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

	// Original routes
	uiRouter.HandleFunc("/", handlers.PublicTimelineHandler).Methods("GET")
	uiRouter.HandleFunc("/timeline", handlers.PersonalTimelineHandler).Methods("GET")
	uiRouter.HandleFunc("/register", handlers.RegisterHandler) // Matches standard form submissions
	uiRouter.HandleFunc("/login", handlers.LoginHandler)
	uiRouter.HandleFunc("/logout", handlers.LogoutHandler)
	uiRouter.HandleFunc("/user/follow/{username}", handlers.FollowUser).Methods("GET")
	uiRouter.HandleFunc("/user/unfollow/{username}", handlers.UnfollowUser).Methods("GET")
	uiRouter.HandleFunc("/user/{username}", handlers.UserTimelineHandler).Methods("GET")
	uiRouter.HandleFunc("/add_message", handlers.AddMessageHandler).Methods("POST")
	fmt.Println("Server running on port 8080...")
	//log.Fatal(http.ListenAndServe(":8000", authMiddleware(router)))
}
