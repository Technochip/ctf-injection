package db

import "ctf-host-header-injection/internal/models"

var Users = map[string]models.User{
	"svc_internal": {
		Username: "svc_internal",
		Password: "ChangeMe_2024!",
		IsAdmin:  true,
	},
}

var Sessions = map[string]string{}

func AddUser(username, password string, isAdmin bool) bool {
	if _, exists := Users[username]; exists {
		return false
	}
	Users[username] = models.User{
		Username: username,
		Password: password,
		IsAdmin:  isAdmin,
	}
	return true
}

func ValidateUser(username, password string) (models.User, bool) {
	user, exists := Users[username]
	if !exists || user.Password != password {
		return models.User{}, false
	}
	return user, true
}

func CreateSession(token, username string) {
	Sessions[token] = username
}

func GetUserFromSession(token string) (string, bool) {
	username, exists := Sessions[token]
	return username, exists
}