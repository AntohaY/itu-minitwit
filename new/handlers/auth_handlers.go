package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"minitwit/app"
	"minitwit/domains"
	. "minitwit/helpers/flashes"
	"minitwit/helpers/requestctx"
	. "minitwit/types"

	"golang.org/x/crypto/bcrypt"
)

// RegisterHandler manages user sign-ups by validating form data and saving new users to the DB.
func RegisterHandler(store domains.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		requestID := requestctx.RequestIDFromRequest(r)
		slog.Debug("register handler called", "method", r.Method, "request_id", requestID)

		user := r.Context().Value("user")
		if user != nil {
			slog.Info("register skipped for authenticated user", "request_id", requestID)
			SetFlash(w, "You are already logged in as "+user.(domains.User).Username)
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
			slog.Debug("register attempt", "username", username, "request_id", requestID)

			exists, err := store.Exists(ctx, username)

			if username == "" {
				errMsg = "You have to enter a username"
			} else if email == "" || !strings.Contains(email, "@") {
				errMsg = "You have to enter a valid email address"
			} else if password == "" {
				errMsg = "You have to enter a password"
			} else if password != password2 {
				errMsg = "The two passwords do not match"
			} else if err != nil {
				errMsg = "Database error while checking username"
			} else if exists {
				errMsg = "The username is already taken"
			} else {
				hashedBytes, hashErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				if hashErr != nil {
					slog.Error("password hashing error", "error", hashErr.Error(), "request_id", requestID)
					errMsg = "Internal server error"
				} else {
					// FIX: Explicitly use domains.User so it matches the store interface perfectly
					newUser := domains.User{
						Username: username,
						Email:    email,
						Password: string(hashedBytes),
					}

					if err := store.Create(ctx, newUser); err != nil {
						slog.Error("registration database error", "error", err.Error(), "request_id", requestID)

						data := TimelineUserData{
							PageTitle: "Register",
							Flashes:   []string{"Database error occurred"},
						}
						app.RenderTemplate(w, "register.html", data)
						return
					}

					slog.Info("registration successful", "username", username, "request_id", requestID)
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
			}
		}

		data := TimelineUserData{
			PageTitle: "Register",
			Flashes:   []string{},
		}

		if errMsg != "" {
			slog.Warn("registration validation failed", "reason", errMsg, "request_id", requestID)
			data.Flashes = append(data.Flashes, errMsg)
		}
		slog.Debug("render register page", "request_id", requestID)
		app.RenderTemplate(w, "register.html", data)
	}
}

// LoginHandler handles user authentication
func LoginHandler(store domains.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		requestID := requestctx.RequestIDFromRequest(r)
		slog.Debug("login handler called", "method", r.Method, "request_id", requestID)

		user := r.Context().Value("user")
		if user != nil {
			slog.Info("login skipped for authenticated user", "request_id", requestID)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		var flashes []string

		if r.Method == http.MethodPost {
			r.ParseForm()
			username := r.FormValue("username")
			password := r.FormValue("password")
			slog.Debug("login attempt", "username", username, "request_id", requestID)

			// MAGIC: We use the interface now!
			foundUser, err := store.GetUserByUsername(ctx, username)

			if err != nil {
				slog.Warn("login failed", "reason", "user_not_found_or_db_error", "request_id", requestID)
				flashes = append(flashes, "Invalid username")
			} else {
				// FALLBACK MECHANISM: Try bcrypt first.
				err = bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(password))

				// If bcrypt fails, try your old app.CheckPasswordHash so existing users aren't locked out!
				if err != nil && !app.CheckPasswordHash(password, foundUser.Password) {
					slog.Warn("login failed", "reason", "invalid_password", "request_id", requestID)
					flashes = append(flashes, "Invalid password")
				} else {
					session, _ := app.Store.Get(r, "minitwit-session")

					// Convert the integer ID from domains.User to a string for the session
					session.Values["user_id"] = foundUser.ID.Hex()
					session.Save(r, w)
					slog.Info("login successful", "request_id", requestID)
					http.Redirect(w, r, "/", http.StatusFound)
					return
				}
			}
		}

		slog.Debug("render login page", "request_id", requestID)
		// Assuming RenderTemplate handles your old `nil` properly, but injected Flashes just in case
		app.RenderTemplate(w, "login.html", map[string]interface{}{"Flashes": flashes})
	}
}

// LogoutHandler handles user logout
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	requestID := requestctx.RequestIDFromRequest(r)
	slog.Debug("logout handler called", "request_id", requestID)
	session, _ := app.Store.Get(r, "minitwit-session")
	session.AddFlash("You were logged out")
	for k := range session.Values {
		delete(session.Values, k)
	}
	if err := session.Save(r, w); err != nil {
		slog.Error("logout session save error", "error", err.Error(), "request_id", requestID)
	} else {
		slog.Info("logout successful", "request_id", requestID)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}
