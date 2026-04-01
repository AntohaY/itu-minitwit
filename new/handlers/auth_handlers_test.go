package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"minitwit/domains"
)

// ==========================================
// 1. THE MOCK (The "Plastic Hammer")
// ==========================================

// MockUserStore acts like our database, but it just saves data in RAM (a map).
type MockUserStore struct {
	users map[string]domains.User
}

// Exists checks our RAM map to see if the user is there.
func (m *MockUserStore) Exists(ctx context.Context, username string) (bool, error) {
	_, exists := m.users[username]
	return exists, nil
}

// Create saves the new user into our RAM map.
func (m *MockUserStore) Create(ctx context.Context, user domains.User) error {
	m.users[user.Username] = user
	return nil
}

// GetUserByUsername fetches the user from our RAM map.
func (m *MockUserStore) GetUserByUsername(ctx context.Context, username string) (domains.User, error) {
	user, exists := m.users[username]
	if !exists {
		return domains.User{}, errors.New("user not found")
	}
	return user, nil
}

// ==========================================
// 2. THE UNIT TEST
// ==========================================

func TestRegisterHandler_Success(t *testing.T) {
	// 1. SETUP: Create our fake database and initialize the map
	mockStore := &MockUserStore{
		users: make(map[string]domains.User),
	}

	// 2. INJECT: Give the fake database to our handler
	handler := RegisterHandler(mockStore)

	// 3. FAKE DATA: Create the form data a user would type into the browser
	formData := url.Values{}
	formData.Set("username", "testuser")
	formData.Set("email", "test@example.com")
	formData.Set("password", "secret123")
	formData.Set("password2", "secret123")

	// 4. FAKE REQUEST: Build an HTTP POST request with our form data
	req, err := http.NewRequest(http.MethodPost, "/register", strings.NewReader(formData.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded") // Tell the server it's a form

	// 5. RECORDER: This acts like the user's browser, recording the server's response
	rr := httptest.NewRecorder()

	// 6. EXECUTE: Fire the fake request at the handler!
	handler.ServeHTTP(rr, req)

	// 7. ASSERT: Check if the application did what we expected!

	// Did it redirect us to /login like it's supposed to on success?
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusFound)
	}

	// Did it actually save the user in our fake database?
	savedUser, exists := mockStore.users["testuser"]
	if !exists {
		t.Errorf("Expected user 'testuser' to be saved in the database, but they weren't!")
	}

	// Did it hash the password correctly? (It shouldn't be plain text!)
	if savedUser.Password == "secret123" {
		t.Errorf("Security flaw! The password was saved as plain text instead of being hashed.")
	}
}
