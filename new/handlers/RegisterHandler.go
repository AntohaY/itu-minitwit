package handlers

// import (
// 	"context"
// 	"log"
// 	"net/http"
// 	"strings"
// 	"time"

// 	. "minitwit/helpers"
// 	. "minitwit/types"

// 	"go.mongodb.org/mongo-driver/bson"
// 	"go.mongodb.org/mongo-driver/bson/primitive"
// )

// // RegisterHandler manages user sign-ups by validating form data and saving new users to the DB.
// // It prevents logged-in users from re-registering and handles error reporting via the UI.
// func RegisterHandler(w http.ResponseWriter, r *http.Request) {
// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 	defer cancel()

// 	user := r.Context().Value("user")
// 	if user != nil {
// 		setFlash(w, "You are already logged in as "+user.(User).Username)
// 		http.Redirect(w, r, "/", http.StatusFound)
// 		return
// 	}

// 	errMsg := ""
// 	if r.Method == http.MethodPost {
// 		r.ParseForm()
// 		username := r.FormValue("username")
// 		email := r.FormValue("email")
// 		password := r.FormValue("password")
// 		password2 := r.FormValue("password2")

// 		if username == "" {
// 			errMsg = "You have to enter a username"
// 		} else if email == "" || !strings.Contains(email, "@") {
// 			errMsg = "You have to enter a valid email address"
// 		} else if password == "" {
// 			errMsg = "You have to enter a password"
// 		} else if password != password2 {
// 			errMsg = "The two passwords do not match"
// 		} else if getUserID(username) != primitive.NilObjectID {
// 			errMsg = "The username is already taken"
// 		} else {
// 			newUser := User{
// 				Username: username,
// 				Email:    email,
// 				PW:       password,
// 				HashedPW: password,
// 			}
// 			db.Collection("user").InsertOne(ctx, newUser)
// 			http.Redirect(w, r, "/login", http.StatusFound)
// 			return
// 		}
// 	}

// 	data := TimelineUserData{
// 		PageTitle: "Register",
// 		Flashes:   []string{},
// 	}

// 	if errMsg != "" {
// 		log.Println("Registration error:", errMsg)
// 		data.Flashes = append(data.Flashes, errMsg)
// 	}
// 	RenderTemplate(w, "register.html", data)
// }

// func getUserID(username string) primitive.ObjectID {
// 	// Create a variable to hold the answer
// 	var result struct {
// 		ID primitive.ObjectID `bson:"_id"` //it force ID to be 12 bytes of hex data
// 	}
// 	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	// Search the "user" collection
// 	filter := bson.M{"username": username}
// 	// we fill result (on the end in right), if we will have error it is assign on the left side
// 	err := db.Collection("user").FindOne(ctx, filter).Decode(&result)
// 	// Check if assign operation thrown an error
// 	if err != nil {
// 		return primitive.NilObjectID
// 	}
// 	return result.ID
// }
