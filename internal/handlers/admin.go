package handlers

import (
	"fmt"
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
		http.Error(w, "403 Forbidden: You don't have admin privileges", http.StatusForbidden)
		return
	}

	forwardedHost := r.Header.Get("X-Forwarded-Host")
	if forwardedHost != "127.0.0.1" && forwardedHost != "localhost" {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Proxy Error: Request blocked by access policy.\n\n")
		fmt.Fprintf(w, "Request Details:\n")
		fmt.Fprintf(w, "  Host: %s\n", r.Host)
		fmt.Fprintf(w, "  X-Forwarded-Host: %s\n", forwardedHost)
		fmt.Fprintf(w, "  X-Forwarded-For: %s\n", r.Header.Get("X-Forwarded-For"))
		fmt.Fprintf(w, "\nAccess to this resource is restricted to internal services only.\n")
		fmt.Fprintf(w, "Expected internal host. Got: '%s'\n", forwardedHost)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Welcome to the admin panel, " + username + "!\n"))
	w.Write([]byte("FLAG{m4ss_h34d3r_4dm1n_byp4ss}\n"))
}
