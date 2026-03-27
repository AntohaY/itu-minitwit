package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var db *mongo.Database

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

	// 1. Connect to MongoDB
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017" // fallback
	}

	// Set a 10-second timeout for the initial connection phase
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		slog.Error("failed to initialize MongoDB client", "error", err.Error())
		os.Exit(1)
	}

	// CLEANUP: Ensure we close the DB connection when the bot shuts down
	defer func() {
		if err = client.Disconnect(context.Background()); err != nil {
			slog.Warn("error disconnecting MongoDB", "error", err.Error())
		}
	}()

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		slog.Error("could not ping MongoDB", "error", err.Error())
		os.Exit(1)
	}

	db = client.Database("test")
	slog.Info("bot connected to MongoDB")

	token := os.Getenv("DISCORD_TOKEN")
	if token == "" {
		slog.Error("DISCORD_TOKEN environment variable not set")
		os.Exit(1)
	}

	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		slog.Error("failed to create Discord session", "error", err.Error())
		os.Exit(1)
	}

	dg.AddHandler(messageCreate)

	err = dg.Open()
	if err != nil {
		slog.Error("failed to open Discord connection", "error", err.Error())
		os.Exit(1)
	}

	slog.Info("bot running")
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	// Gracefully shut down the Discord session
	dg.Close()
	slog.Info("bot shutting down")
}

func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author.ID == s.State.User.ID {
		return
	}

	if m.Content == "!users" {
		collection := db.Collection("user")

		reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer reqCancel()

		count, err := collection.CountDocuments(reqCtx, bson.D{})
		if err != nil {
			s.ChannelMessageSend(m.ChannelID, "Sorry, I couldn't reach the database right now.")
			slog.Error("failed counting users", "error", err.Error())
			return
		}

		response := fmt.Sprintf("There are currently %d users registered in MiniTwit!", count)
		s.ChannelMessageSend(m.ChannelID, response)
	}
}
