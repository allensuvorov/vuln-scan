package main

import (
	"log"
	"net/http"
	"time"

	"github.com/allensuvorov/vuln-scan-query/internal/api"
	"github.com/allensuvorov/vuln-scan-query/internal/githubfetcher"
	"github.com/allensuvorov/vuln-scan-query/internal/service"
	"github.com/allensuvorov/vuln-scan-query/internal/storage"
)

func main() {
	// Initialize the HTTP client with a timeout.
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Create instances of GitHubFetcher.
	fetcher := githubfetcher.New(httpClient)

	// Create instances of SQLiteStorage.
	sqliteStorage, err := storage.NewSQLiteStorage("vulns.db")
	if err != nil {
		log.Fatalf("failed to init storage: %v", err)
	}

	// Create instances of Service with the fetcher and sqliteStorage.
	svc := service.New(fetcher, sqliteStorage)

	// Initialize the API handler with the service.
	handler := api.New(svc)

	// Set up the HTTP routes.
	mux := http.NewServeMux()

	mux.HandleFunc("POST /scan", handler.ScanHandler)
	mux.HandleFunc("POST /query", handler.QueryHandler)

	log.Println("Server starting on :8080")
	err = http.ListenAndServe(":8080", mux)
	log.Fatal(err)
}
