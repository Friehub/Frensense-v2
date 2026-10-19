package main

import (
	"fmt"
	"net/http"
)

func h(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>%s</h1>", r.URL.Query().Get("n"))
}
