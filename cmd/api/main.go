package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "OK")
	})

	log.Print("starting server on :8080")

	err := http.ListenAndServe(":8080", nil)
	log.Fatal(err)
}

// This is a simple HTTP server that responds to health check requests.
