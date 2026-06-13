package handlers

import (
	"net/http"

	"ctf-host-header-injection/internal/db"
)

func AdminHandler(w http.ResponseWriter, r *http.Request) {
	// Step 1: Check session - must be logged in
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

	// Step 2: Check X-Forwarded-Host header (the vulnerability)
	forwardedHost := r.Header.Get("X-Forwarded-Host")

	if forwardedHost != "127.0.0.1" && forwardedHost != "localhost" {
		http.Error(w, "403 Forbidden: Admin panel is only accessible from localhost", http.StatusForbidden)
		return
	}

	// Step 3: Access granted - but check WHO is asking
	if username != "svc_internal" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to the internal panel, " + username + ".\n"))
		w.Write([]byte("Hmm, this looks like an internal service dashboard, but you don't have the right privileges to see sensitive data.\n"))
		w.Write([]byte("(Hint: not all internal accounts are created equal...)\n"))
		return
	}

	// svc_internal gets the real flag
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Welcome to the admin panel, " + username + "!\n"))
	w.Write([]byte("FLAG{h0st_h34d3r_4dm1n_byp4ss}\n"))
}
