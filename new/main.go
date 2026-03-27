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
	"log/slog"
	"minitwit/api"
	"minitwit/handlers"
	"net/http" // built-in library which replace flask
	"os"       // read environment variables (for example DB_IP)
	"strings"
	_ "time/tzdata"

	"minitwit/app"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"

	. "minitwit/db_setup"

	. "minitwit/middleware"

	. "minitwit/types"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus imports

func main() {
	logLevel := &slog.LevelVar{}
	logLevel.Set(slog.LevelInfo)
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LOG_LEVEL"))) {
	case "debug":
		logLevel.Set(slog.LevelDebug)
	case "warn", "warning":
		logLevel.Set(slog.LevelWarn)
	case "error":
		logLevel.Set(slog.LevelError)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))

	reg := prometheus.NewRegistry()

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		HttpResponsesTotal,
		HttpDuration,
	)

	app.LoadPreviousErrors()
	mongoURI := os.Getenv("MONGO_URI")
	app.Config = Configuration{
		Debug:     true,
		SecretKey: "development key",
		MongoURI:  mongoURI,
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

	router := mux.NewRouter().StrictSlash(true)

	router.Use(MetricsMiddleware)
	router.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Detect the Simulator / API Request
		isAPIRequest := r.Header.Get("Authorization") != "" ||
			strings.Contains(r.Header.Get("Accept"), "application/json") ||
			strings.Contains(r.Header.Get("Content-Type"), "application/json")

		if isAPIRequest {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// 2. Handle standard Web Browser UI requests
		// Wrap the UI handler in the auth middleware dynamically so r.Context().Value("user") still works
		uiNotFound := authMiddleware(http.HandlerFunc(handlers.NotFoundHandler))
		uiNotFound.ServeHTTP(w, r)
	})
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// ==========================================
	// 3. API ROUTES (Simulator)
	// ==========================================
	apiHandler := api.NewAPI(app.DB)

	router.HandleFunc("/latest", apiHandler.GetLatestHandler).Methods("GET")

	// The "Headers" matcher ensures JSON requests go to the API, not UI
	router.HandleFunc("/register", apiHandler.RegisterHandler).Methods("POST").
		HeadersRegexp("Content-Type", "application/json.*")

	// Wrapping the protected API endpoints with the API's specific Basic Auth middleware
	router.HandleFunc("/msgs", apiHandler.AuthMiddleware(apiHandler.GetMessagesHandler)).Methods("GET")
	router.HandleFunc("/msgs/{username}", apiHandler.AuthMiddleware(apiHandler.UserMessagesHandler)).Methods("GET", "POST")
	router.HandleFunc("/fllws/{username}", apiHandler.AuthMiddleware(apiHandler.FollowsHandler)).Methods("GET", "POST")

	// ==========================================
	// 4. UI ROUTES (Web Browser)
	// ==========================================
	uiRouter := router.PathPrefix("/").Subrouter()
	uiRouter.Use(BeforeAfterMiddleware)
	uiRouter.Use(authMiddleware)

	uiRouter.HandleFunc("/", handlers.PublicTimelineHandler).Methods("GET")
	uiRouter.HandleFunc("/login", handlers.LoginHandler)
	uiRouter.HandleFunc("/register", handlers.RegisterHandler)

	uiRouter.HandleFunc("/timeline", handlers.PersonalTimelineHandler).Methods("GET")
	uiRouter.HandleFunc("/logout", handlers.LogoutHandler)
	uiRouter.HandleFunc("/user/follow/{username}", handlers.FollowUser).Methods("GET")
	uiRouter.HandleFunc("/user/unfollow/{username}", handlers.UnfollowUser).Methods("GET")
	uiRouter.HandleFunc("/user/{username}", handlers.UserTimelineHandler).Methods("GET")
	uiRouter.HandleFunc("/add_message", handlers.AddMessageHandler).Methods("POST")
	slog.Info("server starting", "port", 8080)
	if err := http.ListenAndServe(":8080", router); err != nil {
		slog.Error("server stopped", "error", err.Error())
		os.Exit(1)
	}
}
