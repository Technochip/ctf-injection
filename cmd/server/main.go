package main

import (
	"fmt"
	"log"
	"net/http"

	"ctf-host-header-injection/internal/handlers"
)

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", handlers.RegisterHandler)
	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/admin", handlers.AdminHandler)

	log.Println("Server starting on :4000")
	err := http.ListenAndServe(":4000", nil)
	if err != nil {
		log.Fatal(err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Welcome to the CTF Challenge!")
}
