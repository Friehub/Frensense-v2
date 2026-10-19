package main

import (
	"net/http"
	"os/exec"
)

func h(w http.ResponseWriter, r *http.Request) {
	exec.Command("ls", r.URL.Query().Get("d")).Run()
}
