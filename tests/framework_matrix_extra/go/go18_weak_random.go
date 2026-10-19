package main

import (
	"fmt"
	"math/rand"
	"net/http"
)

func h(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, rand.Int63())
}
