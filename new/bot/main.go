package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
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
		log.Fatal("Error initializing MongoDB client: ", err)
	}

	// CLEANUP: Ensure we close the DB connection when the bot shuts down
	defer func() {
		if err = client.Disconnect(context.Background()); err != nil {
			log.Println("Error disconnecting from MongoDB:", err)
		}
	}()

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Fatal("Could not ping MongoDB: ", err)
	}

	db = client.Database("minitwit")
	fmt.Println("Bot successfully connected and pinged MongoDB!")

	token := os.Getenv("DISCORD_TOKEN")
	if token == "" {
		log.Fatal("DISCORD_TOKEN environment variable not set")
	}

	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		log.Fatal("Error creating Discord session: ", err)
	}

	dg.AddHandler(messageCreate)

	err = dg.Open()
	if err != nil {
		log.Fatal("Error opening Discord connection: ", err)
	}

	fmt.Println("Bot is now running. Press CTRL-C to exit.")
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	// Gracefully shut down the Discord session
	dg.Close()
	fmt.Println("Bot shutting down...")
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
			log.Println("DB Count Error:", err)
			return
		}

		response := fmt.Sprintf("There are currently %d users registered in MiniTwit!", count)
		s.ChannelMessageSend(m.ChannelID, response)
	}
}
