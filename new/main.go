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
	"log"
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

// Prometheus imports
import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	reg := prometheus.NewRegistry()

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		HttpResponsesTotal,
		HttpDuration,
	)

	app.LoadPreviousErrors()

	app.Config = Configuration{
		Debug:     true,
		SecretKey: "development key",
		MongoURI:  "mongodb://dbserver:27017",
	}

	if envKey := os.Getenv("SECRET_KEY"); envKey != "" {
		app.Config.SecretKey = envKey
	}
	if envMongo := os.Getenv("MONGO_URI"); envMongo != "" {
		app.Config.MongoURI = envMongo
	}

	app.Store = sessions.NewCookieStore([]byte(app.Config.SecretKey))
	app.Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   false,
	}

	app.DBClient, app.DB = ResolveClientDB(app.Config)
	authMiddleware := AuthMiddleware(app.Store, app.DB)

	router := mux.NewRouter()

	router.Use(MetricsMiddleware)
	router.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	router.NotFoundHandler = authMiddleware(http.HandlerFunc(handlers.NotFoundHandler))
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// ==========================================
	// 3. API ROUTES (Simulator)
	// ==========================================
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
	publicUI := router.PathPrefix("/").Subrouter()
	publicUI.Use(BeforeAfterMiddleware)
	publicUI.Use(authMiddleware)

	publicUI.HandleFunc("/", handlers.PublicTimelineHandler).Methods("GET")
	publicUI.HandleFunc("/login", handlers.LoginHandler)
	publicUI.HandleFunc("/register", handlers.RegisterHandler)

	protectedUI := router.PathPrefix("/").Subrouter()
	protectedUI.Use(BeforeAfterMiddleware)
	protectedUI.Use(authMiddleware)

	protectedUI.HandleFunc("/timeline", handlers.PersonalTimelineHandler).Methods("GET")
	protectedUI.HandleFunc("/logout", handlers.LogoutHandler)
	protectedUI.HandleFunc("/user/follow/{username}", handlers.FollowUser).Methods("GET")
	protectedUI.HandleFunc("/user/unfollow/{username}", handlers.UnfollowUser).Methods("GET")
	protectedUI.HandleFunc("/user/{username}", handlers.UserTimelineHandler).Methods("GET")
	protectedUI.HandleFunc("/add_message", handlers.AddMessageHandler).Methods("POST")
	fmt.Println("Server running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", router))
}
