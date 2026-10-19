package main

import (
	"net/http"
)

type cache struct{}

func (cache) Query(k string) string { return k }

var c cache

func h(w http.ResponseWriter, r *http.Request) {
	_ = c.Query(r.URL.Query().Get("id"))
}
