package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func h(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("f"))
	f, _ := os.Open(filepath.Join("/data", name))
	_ = f
}
