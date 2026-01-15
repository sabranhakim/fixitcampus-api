package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
)

var db *sql.DB
var jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))

type Ticket struct {
	ID          int    `json:"id"`
	UserID      int    `json:"user_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

type Claims struct {
	Data struct {
		UserID int    `json:"user_id"`
		Role   string `json:"role"`
	} `json:"data"`
	jwt.RegisteredClaims
}

//// ================= MIDDLEWARE =================
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"Authorization header required"}`, http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, `{"error":"Invalid or expired token"}`, http.StatusUnauthorized)
			return
		}

		r.Header.Set("X-User-ID", fmt.Sprintf("%d", claims.Data.UserID))
		r.Header.Set("X-User-Role", claims.Data.Role)

		next.ServeHTTP(w, r)
	}
}

//// ================= MAIN =================
func main() {
	psqlInfo := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USERNAME"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_DATABASE"),
	)

	var err error
	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatalf("DB connection error: %v", err)
	}
	defer db.Close()

	createTable()

	http.HandleFunc("/tickets", handleTickets)

	log.Println("Ticket service running on 0.0.0.0:8082")
	log.Fatal(http.ListenAndServe("0.0.0.0:8082", nil))
}

//// ================= HANDLER =================
func handleTickets(w http.ResponseWriter, r *http.Request) {
	authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		path := strings.TrimPrefix(r.URL.Path, "/tickets")
		userRole := r.Header.Get("X-User-Role")

		switch r.Method {

		case http.MethodGet:
			if path != "" && path != "/" {
				id, _ := strconv.Atoi(strings.Trim(path, "/"))
				getTicket(w, r, id)
			} else {
				if userRole == "admin" {
					getAllTickets(w, r)
				} else {
					getUserTickets(w, r)
				}
			}

		case http.MethodPost:
			createTicket(w, r)

		case http.MethodPut:
			if userRole != "admin" {
				http.Error(w, `{"error":"Admin access required"}`, http.StatusForbidden)
				return
			}
			id, _ := strconv.Atoi(strings.Trim(path, "/"))
			updateTicketStatus(w, r, id)

		default:
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		}
	}).ServeHTTP(w, r)
}

//// ================= DB =================
func createTable() {
	query := `
	CREATE TABLE IF NOT EXISTS tickets (
		id SERIAL PRIMARY KEY,
		user_id INT NOT NULL,
		title VARCHAR(255) NOT NULL,
		description TEXT,
		status VARCHAR(50) DEFAULT 'open',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`
	if _, err := db.Exec(query); err != nil {
		log.Fatalf("Create table error: %v", err)
	}
}

func createTicket(w http.ResponseWriter, r *http.Request) {
	var t Ticket
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		http.Error(w, `{"error":"Invalid body"}`, http.StatusBadRequest)
		return
	}

	userID, _ := strconv.Atoi(r.Header.Get("X-User-ID"))
	t.UserID = userID

	err := db.QueryRow(
		`INSERT INTO tickets (user_id, title, description)
		 VALUES ($1, $2, $3)
		 RETURNING id, status`,
		t.UserID, t.Title, t.Description,
	).Scan(&t.ID, &t.Status)

	if err != nil {
		http.Error(w, `{"error":"Insert failed"}`, http.StatusInternalServerError)
		return
	}

	go func() {
		data, _ := json.Marshal(map[string]string{"event": "ticket_created"})
		http.Post("http://reporting-service:5000/reports/update", "application/json", bytes.NewBuffer(data))
	}()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(t)
}

func getAllTickets(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, user_id, title, description, status FROM tickets ORDER BY id DESC")
	if err != nil {
		http.Error(w, `{"error":"Query failed"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var tickets []Ticket
	for rows.Next() {
		var t Ticket
		rows.Scan(&t.ID, &t.UserID, &t.Title, &t.Description, &t.Status)
		tickets = append(tickets, t)
	}

	json.NewEncoder(w).Encode(tickets)
}

func getUserTickets(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.Atoi(r.Header.Get("X-User-ID"))

	rows, err := db.Query(
		"SELECT id, user_id, title, description, status FROM tickets WHERE user_id=$1 ORDER BY id DESC",
		userID,
	)
	if err != nil {
		http.Error(w, `{"error":"Query failed"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var tickets []Ticket
	for rows.Next() {
		var t Ticket
		rows.Scan(&t.ID, &t.UserID, &t.Title, &t.Description, &t.Status)
		tickets = append(tickets, t)
	}

	json.NewEncoder(w).Encode(tickets)
}

func getTicket(w http.ResponseWriter, r *http.Request, id int) {
	var t Ticket
	err := db.QueryRow(
		"SELECT id, user_id, title, description, status FROM tickets WHERE id=$1",
		id,
	).Scan(&t.ID, &t.UserID, &t.Title, &t.Description, &t.Status)

	if err != nil {
		http.Error(w, `{"error":"Ticket not found"}`, http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(t)
}

func updateTicketStatus(w http.ResponseWriter, r *http.Request, id int) {
	var payload struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"Invalid body"}`, http.StatusBadRequest)
		return
	}

	_, err := db.Exec("UPDATE tickets SET status=$1 WHERE id=$2", payload.Status, id)
	if err != nil {
		http.Error(w, `{"error":"Update failed"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Status updated"})
}