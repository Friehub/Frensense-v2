package main

import (
	"net/http"
	"os"
)

func h(w http.ResponseWriter, r *http.Request) {
	f, _ := os.Open(r.URL.Query().Get("f"))
	_ = f
}
