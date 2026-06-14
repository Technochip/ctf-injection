package handlers

import (
	"encoding/json"
	"net/http"

	"ctf-host-header-injection/internal/db"
)

func AdminHandler(w http.ResponseWriter, r *http.Request) {
	// CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Forwarded-Host")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	// Handle browser preflight request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Only allow POST for login
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds credentials

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, ok := db.ValidateUser(creds.Username, creds.Password)
	if !ok {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if !user.IsAdmin {
		http.Error(w, "403 Forbidden: You don't have admin privileges", http.StatusForbidden)
		return
	}

	forwardedHost := r.Header.Get("X-Forwarded-Host")
	if forwardedHost != "127.0.0.1" && forwardedHost != "localhost" {
		http.Error(w, "Proxy Error: Request blocked by internal access policy", http.StatusForbidden)
		return
	}

	w.WriteHeader(http.StatusOK)

	response := map[string]string{
		"message": "Welcome to the admin panel, " + user.Username,
		"flag":    "flag{m4ss_h34d3r_4dm1n_byp4ss}",
	}

	json.NewEncoder(w).Encode(response)
}