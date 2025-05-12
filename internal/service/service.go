package service

import (
	"context"
	"errors"
	"fmt"
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

func NewService(fetcher GitHubFetcher, storage Storage) *Service {
	return &Service{
		fetcher: fetcher,
		storage: storage,
	}
}

func (s *Service) Scan(ctx context.Context, req entity.ScanRequest) error {
	if req.Repo == "" || len(req.Files) == 0 {
		return errors.New("repo and files must be provided")
	}

	// Fetch .json files
	fileData, err := s.fetcher.FetchFiles(ctx, req.Repo, req.Files)
	if err != nil {
		return fmt.Errorf("fetch failed: %w", err)
	}

	// Parse each file
	var allVulns []entity.Vulnerability
	now := time.Now()

	for fileName, data := range fileData {
		vulns, err := ParseVulnerabilities(data, fileName, now)
		if err != nil {
			return fmt.Errorf("parse failed for %s: %w", fileName, err)
		}
		allVulns = append(allVulns, vulns...)
	}

	// Save all to storage
	return s.storage.SaveVulnerabilities(ctx, allVulns)
}

func (s *Service) Query(ctx context.Context, req entity.QueryRequest) ([]entity.Vulnerability, error) {
	severity, ok := req.Filters["severity"]
	if !ok || severity == "" {
		return nil, errors.New("missing severity filter")
	}
	return s.storage.QueryBySeverity(ctx, severity)
}
