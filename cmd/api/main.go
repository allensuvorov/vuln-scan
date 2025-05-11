package main

import (
	"log"
	"net/http"

	"github.com/allensuvorov/vuln-scan-query/internal/api"
)

func main() {
	mux := http.NewServeMux()

	handler := api.NewHandler()

	mux.HandleFunc("POST /scan", handler.ScanHandler)
	mux.HandleFunc("POST /query", handler.QueryHandler)

	log.Println("Server starting on :8080")
	err := http.ListenAndServe(":8080", mux)
	log.Fatal(err)
}
