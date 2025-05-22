package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/allensuvorov/vuln-scan-query/internal/domain/entity"
)

type GitHubFetcher interface {
	FetchFiles(ctx context.Context, repo string, files []string) (map[string][]byte, error)
}

type Storage interface {
	SaveVulnerabilities(ctx context.Context, vulns []entity.Vulnerability) error
	QueryBySeverity(ctx context.Context, severity string) ([]entity.Vulnerability, error)
}

type Service struct {
	fetcher GitHubFetcher
	storage Storage
}

func New(fetcher GitHubFetcher, storage Storage) *Service {
	return &Service{
		fetcher: fetcher,
		storage: storage,
	}
}

func (s *Service) Scan(ctx context.Context, req entity.ScanRequest) error {
	if req.Repo == "" || len(req.Files) == 0 {
		return errors.New("repo and files must be provided")
	}

	const workerCount = 3 // Fetch concurrency limit

	var (
		wg       sync.WaitGroup
		parsed   []entity.Vulnerability
		jobs     = make(chan string)
		vulnChan = make(chan entity.Vulnerability, 3)
	)

	// Start worker pool
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			log.Printf("Worker %v - start", workerID)
			defer wg.Done()
			for file := range jobs {
				// Fetch
				filesData, err := s.fetcher.FetchFiles(ctx, req.Repo, []string{file})
				if err != nil {
					fmt.Printf("⚠️  Worker %d: Failed to fetch %s: %v\n", workerID, file, err)
					continue
				}

				data := filesData[file]
				if len(data) == 0 {
					fmt.Printf("⚠️  Worker %d: No data in file %s\n", workerID, file)
					continue
				}

				// Parse
				vulns, err := ParseVulnerabilities(data, file, time.Now())
				if err != nil {
					fmt.Printf("⚠️  Worker %d: Failed to parse %s: %v\n", workerID, file, err)
					continue
				}

				// Send to channel
				for _, vuln := range vulns {
					vulnChan <- vuln
				}
			}
		}(i + 1)
	}

	// Send jobs to workers
	go func() {
		log.Printf("Send files to jobs channel - start")

		for _, file := range req.Files {
			jobs <- file
		}

		// Close jobs channel, so workers know to stop
		close(jobs)
		log.Printf("Send files to jobs channel - end")
	}()

	// In a separate goroutine wait for all workers to finish and close vulnChan
	go func() {
		log.Printf("WaitGroup - Waiting for all gouroutines to finish - start")
		wg.Wait()
		close(vulnChan)
		log.Printf("WaitGroup - Waiting for all gouroutines to finish - end")
	}()

	// Read vulns from vulnChan
	log.Printf("Read vulns from vulnChan - start")
	for vuln := range vulnChan {
		parsed = append(parsed, vuln)
	}
	log.Printf("Read vulns from vulnChan - end")

	// process: jobs -> worker -> vulns ->

	// go jobs ->
	// go workerpool ->
	// go wg.Wait ....

	// vuln reader ->

	// Batch write to DB
	if err := s.storage.SaveVulnerabilities(ctx, parsed); err != nil {
		return fmt.Errorf("saving vulnerabilities: %w", err)
	}

	return nil
}

func (s *Service) Query(ctx context.Context, req entity.QueryRequest) ([]entity.Vulnerability, error) {
	severity, ok := req.Filters["severity"]
	if !ok || severity == "" {
		return nil, errors.New("missing severity filter")
	}
	return s.storage.QueryBySeverity(ctx, severity)
}
