package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func h(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rows, _ := db.Query("SELECT * FROM users WHERE id = '" + id + "'")
	_ = rows
}
