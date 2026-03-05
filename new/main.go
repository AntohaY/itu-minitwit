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

// check if it works
// go run main.go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"

	"minitwit/app"
	. "minitwit/db_setup"
	"minitwit/handlers"
	. "minitwit/middleware"
	. "minitwit/types"
)

func main() {
	// Load Configuration
	app.Config = Configuration{
		Debug:     true,
		SecretKey: "development key",
	}

	// Override from Environment
	if envKey := os.Getenv("SECRET_KEY"); envKey != "" {
		app.Config.SecretKey = envKey
	}

	// Initialize database connection
	app.DBClient, app.DB = ResolveClientDB(app.Config)

	// Setup router
	router := mux.NewRouter()

	// Setup middleware
	authMiddleware := AuthMiddleware(app.Store, app.DB)
	router.Use(BeforeAfterMiddleware)
	router.Use(authMiddleware)

	// Serve static files
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// Register routes
	router.HandleFunc("/", handlers.PublicTimelineHandler).Methods("GET")
	router.HandleFunc("/timeline", handlers.PersonalTimelineHandler).Methods("GET")
	router.HandleFunc("/register", handlers.RegisterHandler)
	router.HandleFunc("/login", handlers.LoginHandler)
	router.HandleFunc("/logout", handlers.LogoutHandler)
	router.HandleFunc("/user/follow/{username}", handlers.FollowUser).Methods("GET")
	router.HandleFunc("/user/unfollow/{username}", handlers.UnfollowUser).Methods("GET")
	router.HandleFunc("/user/{username}", handlers.UserTimelineHandler).Methods("GET")
	router.HandleFunc("/add_message", handlers.AddMessageHandler).Methods("POST")

	// Start server
	log.Fatal(http.ListenAndServe(":5000", router))
}
