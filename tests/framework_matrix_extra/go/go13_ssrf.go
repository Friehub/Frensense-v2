package main

import (
	"net/http"
)

func h(w http.ResponseWriter, r *http.Request) {
	resp, _ := http.Get(r.URL.Query().Get("u"))
	_ = resp
}
