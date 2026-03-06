package flashes

import (
	"encoding/base64"
	"net/http"
	"time"
)

func SetFlash(w http.ResponseWriter, message string) {
	c := &http.Cookie{
		Name:  "flash",
		Value: base64.StdEncoding.EncodeToString([]byte(message)),
		Path:  "/",
	}
	http.SetCookie(w, c)
}

func GetFlash(w http.ResponseWriter, r *http.Request) []string {
	c, err := r.Cookie("flash")
	if err != nil {
		return nil // No flash message
	}

	val, _ := base64.StdEncoding.DecodeString(c.Value)

	http.SetCookie(w, &http.Cookie{
		Name:    "flash",
		MaxAge:  -1,
		Expires: time.Unix(1, 0),
		Path:    "/",
	})

	return []string{string(val)}
}

