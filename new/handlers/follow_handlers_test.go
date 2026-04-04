package handlers

//my plan
// create two users in my struct
//thats our handlers:
// uiRouter.HandleFunc("/user/follow/{username}", handlers.FollowUser).Methods("GET")
//uiRouter.HandleFunc("/user/unfollow/{username}", handlers.UnfollowUser).Methods("GET")
// we should pass two usernames there, but how? one should be this on who function is operating
// seconds name should be passed in {username} in call in endpoint
// as argument we have to pass our struct
// we have to modify handler and function logic, especially this line:
//
//_, insertErr := app.DB.Collection("follower").InsertOne(ctx, bson.M{
//	"who_id":  user.ID,
//	"whom_id": profileUser.ID,
//})

//err := app.DB.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&profileUser)

// our struct should have the same properties as database, so we also need to create struct
// with fields who id and whom id.

//Test to perform:
// user1 follow user2
//1. user 1. dont exist -> http.Error(w, "Unauthorized", http.StatusUnauthorized)
//2. user 2. dont exist -> http.Error(w, "User not found", http.StatusNotFound)
//3. user 1 == user 2 -> http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
//4. user 1 want to follow user 2 -> http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
//5. 2 times follow -> http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
//for unfollow the same procedure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"minitwit/domains"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// 1. Create the Mocks
type FollowMockUserStore struct {
	domains.UserStore // Embed interface
	GetUserFunc       func(ctx context.Context, username string) (domains.User, error)
}

func (m *FollowMockUserStore) GetUserByUsername(ctx context.Context, username string) (domains.User, error) {
	return m.GetUserFunc(ctx, username)
}

type MockFollowStore struct {
	domains.FollowStore
	FollowFunc func(ctx context.Context, whoID, whomID primitive.ObjectID) error
}

func (m *MockFollowStore) Follow(ctx context.Context, whoID, whomID primitive.ObjectID) error {
	return m.FollowFunc(ctx, whoID, whomID)
}

// 2. The Actual Test
func TestFollowUser_Success(t *testing.T) {
	// Setup IDs
	currentUserID := primitive.NewObjectID()
	targetUserID := primitive.NewObjectID()
	targetUsername := "testuser"

	// Configure Mock Behavior
	uMock := &FollowMockUserStore{
		GetUserFunc: func(ctx context.Context, username string) (domains.User, error) {
			return domains.User{ID: targetUserID, Username: targetUsername}, nil
		},
	}

	fMock := &MockFollowStore{
		FollowFunc: func(ctx context.Context, whoID, whomID primitive.ObjectID) error {
			return nil // Success!
		},
	}

	// Create a Request
	req := httptest.NewRequest("GET", "/user/follow/"+targetUsername, nil)

	// Manually inject the "logged in user" into the context
	ctx := context.WithValue(req.Context(), "user", domains.User{ID: currentUserID})
	req = req.WithContext(ctx)

	// Add Gorilla Mux vars
	req = mux.SetURLVars(req, map[string]string{"username": targetUsername})

	rr := httptest.NewRecorder()

	// 3. EXECUTE: Call the handler with our mocks
	handler := FollowUser(fMock, uMock)
	handler.ServeHTTP(rr, req)

	// 4. ASSERT: Did we get a redirect?
	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusSeeOther)
	}

	expectedLocation := "/user/" + targetUsername
	if loc := rr.Header().Get("Location"); loc != expectedLocation {
		t.Errorf("handler redirected to wrong place: got %v want %v", loc, expectedLocation)
	}
}
