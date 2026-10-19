package main

import (
	"net/http"
	"gorm.io/gorm"
)

var db *gorm.DB

func h(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var u struct{ ID string }
	db.Where("id = ?", id).First(&u)
}
