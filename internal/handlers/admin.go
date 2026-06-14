package handlers

import (
	"net/http"

	"ctf-host-header-injection/internal/db"
)

func AdminHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "Unauthorized: please log in", http.StatusUnauthorized)
		return
	}

	username, valid := db.GetUserFromSession(cookie.Value)
	if !valid {
		http.Error(w, "Unauthorized: invalid session", http.StatusUnauthorized)
		return
	}

	user := db.Users[username]
	if !user.IsAdmin {
		http.Error(w, "403 Forbidden: You do not have admin privileges", http.StatusForbidden)
		return
	}

	forwardedHost := r.Header.Get("X-Forwarded-Host")
	if forwardedHost != "127.0.0.1" && forwardedHost != "localhost" {
		http.Error(w, "403 Forbidden: Admin panel is only accessible from localhost", http.StatusForbidden)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Welcome to the admin panel, " + username + "!\n"))
	w.Write([]byte("FLAG{h0st_h34d3r_4dm1n_byp4ss}\n"))
}
