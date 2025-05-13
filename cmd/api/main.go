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

	// Create instances of GitHubFetcher and DummyStorage.
	fetcher := githubfetcher.New(httpClient)

	// dummyStorage := storage.NewDummyStorage()

	sqliteStorage, err := storage.NewSQLiteStorage("vulns.db")
	if err != nil {
		log.Fatalf("failed to init storage: %v", err)
	}

	svc := service.New(fetcher, sqliteStorage)
	// Create the default service with the fetcher and storage.
	// svc := service.New(fetcher, dummyStorage)

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
