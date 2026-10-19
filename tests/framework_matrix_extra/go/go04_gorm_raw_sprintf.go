package main

import (
	"fmt"
	"net/http"
	"gorm.io/gorm"
)

var db *gorm.DB

func h(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var out []map[string]any
	db.Raw(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)).Scan(&out)
}
