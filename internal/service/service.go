package service

import (
	"context"
	"time"
)

// Vulnerability represents a parsed CVE entry
type Vulnerability struct {
	ID             string    `json:"id"`
	Severity       string    `json:"severity"`
	CVSS           float64   `json:"cvss"`
	Status         string    `json:"status"`
	PackageName    string    `json:"package_name"`
	CurrentVersion string    `json:"current_version"`
	FixedVersion   string    `json:"fixed_version"`
	Description    string    `json:"description"`
	PublishedDate  time.Time `json:"published_date"`
	Link           string    `json:"link"`
	RiskFactors    []string  `json:"risk_factors"`

	// Metadata
	SourceFile string    `json:"source_file"`
	ScanTime   time.Time `json:"scan_time"`
}

// ScanRequest is input for /scan
type ScanRequest struct {
	Repo  string   `json:"repo"`
	Files []string `json:"files"`
}

// QueryRequest is input for /query
type QueryRequest struct {
	Filters map[string]string `json:"filters"`
}

// Service is the business logic interface
type Service interface {
	Scan(ctx context.Context, req ScanRequest) error
	Query(ctx context.Context, req QueryRequest) ([]Vulnerability, error)
}
