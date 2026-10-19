package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
)

var db *sql.DB

func h(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		return
	}
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", n))
}
