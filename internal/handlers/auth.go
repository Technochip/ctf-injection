package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"ctf-host-header-injection/internal/db"
)

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"admin"`
}
// The RegisterHandler handles user registration requests.

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if creds.Username == "" || creds.Password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}

	if !db.AddUser(creds.Username, creds.Password, creds.IsAdmin) {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	if creds.IsAdmin {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Admin user registered successfully"))
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User registered successfully"))
	}
}

// The LoginHandler handles user login requests.

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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

	token := generateToken()
	db.CreateSession(token, user.Username)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Login successful. Welcome, " + user.Username))
}

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
