package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	_ "github.com/lib/pq"
)

/*
Endpoints:
- GET /
- POST /api/login
- POST /api/logout
- POST /api/register
- GET /api/room/:id - Get the room's info
- POST /api/room - Create a new room and join it
- PATCH /api/room/:id - Update the room's info
- TODO: POST /api/room/:id - Join an existing room
- TODO: WS /api/room/:id - Get live updates to room's info
- TODO: GET /api/room/:id/leave - Leave a room

TODO: You can be a member of up to 3 rooms at once.
TODO: Rooms are deleted after 10 minutes of no members.
TODO: Implement a rate limit of 3reqs/10min on creating rooms.
*/

var db *sql.DB
var config Config

type Config struct {
	SecureCookies bool   `json:"secureCookies"`
	DatabaseURL   string `json:"databaseUrl"`
}

// TODO: implement e-mail verification option, add forgot password endpoint, room member limit
func main() {
	log.SetOutput(os.Stderr)
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		log.Panicln("Failed to read config file!", err)
	}
	err = json.Unmarshal(configFile, &config)
	if err != nil {
		log.Panicln("Failed to parse config file!", err)
	}
	db, err = sql.Open("postgres", config.DatabaseURL)
	if err != nil {
		log.Panicln("Failed to open connection to database!", err)
	}
	db.SetMaxOpenConns(10)
	CreateSqlTables()
	PrepareSqlStatements()

	// Endpoints
	http.HandleFunc("/", StatusEndpoint)
	http.HandleFunc("/api/login", LoginEndpoint)
	http.HandleFunc("/api/logout", LogoutEndpoint)
	http.HandleFunc("/api/register", RegisterEndpoint)
	http.HandleFunc("/api/room", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			// POST /api/room
			CreateRoom(w, r)
		} else {
			http.Error(w, errorJson("Method Not Allowed!"), http.StatusMethodNotAllowed)
		}
	})
	http.HandleFunc("/api/room/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// GET /api/room/:id and GET /api/room/:id/leave
			GetRoom(w, r)
		} else if r.Method == "PATCH" {
			// POST /api/room/:id
			http.Error(w, errorJson("Not Implemented!"), http.StatusNotImplemented) // TODO
		} else if r.Method == "OPTIONS" {
			// OPTIONS /api/room/:id
			http.Error(w, errorJson("Not Implemented!"), http.StatusNotImplemented) // TODO
		} else {
			http.Error(w, errorJson("Method Not Allowed!"), http.StatusMethodNotAllowed)
		}
	})

	port := "8000"
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}
	log.SetOutput(os.Stdout)
	log.Println("Listening to port " + port)
	log.SetOutput(os.Stderr)
	log.Fatalln(http.ListenAndServe(":"+port, handlers.CORS(
		handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PATCH", "DELETE", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authentication"}),
		handlers.AllowedOrigins([]string{"*"}), // Breaks credentialed auth
		handlers.AllowCredentials(),
	)(http.DefaultServeMux)))
}
