package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func h(w http.ResponseWriter, r *http.Request) {
	var q string
	if v := r.URL.Query().Get("id"); v != "" {
		q = v
	} else {
		q = "0"
	}
	db.Query("SELECT * FROM users WHERE id = " + q)
}
