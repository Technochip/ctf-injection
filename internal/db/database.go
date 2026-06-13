package db

import (
	"ctf-host-header-injection/internal/models"
)

var Users = map[string]models.User{
	// Hidden default user - players might find this via recon
	"svc_internal": {
		Username: "svc_internal",
		Password: "ChangeMe_2024!",
		IsAdmin:  true,
	},
}

// Sessions maps session token -> username
var Sessions = map[string]string{}

// AddUser registers a new user (open registration)
func AddUser(username, password string) bool {
	if _, exists := Users[username]; exists {
		return false // username taken
	}
	Users[username] = models.User{
		Username: username,
		Password: password,
		IsAdmin:  false,
	}
	return true
}

// ValidateUser checks login credentials
func ValidateUser(username, password string) (models.User, bool) {
	user, exists := Users[username]
	if !exists || user.Password != password {
		return models.User{}, false
	}
	return user, true
}

// CreateSession generates a session and stores it
func CreateSession(token, username string) {
	Sessions[token] = username
}

// GetUserFromSession returns username for a session token
func GetUserFromSession(token string) (string, bool) {
	username, exists := Sessions[token]
	return username, exists
}
