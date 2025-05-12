package storage

import (
	"context"
	"fmt"

	"github.com/allensuvorov/vuln-scan-query/internal/domain/entity"
)

// DummyStorage is a mock implementation of the Storage interface for testing purposes.
type DummyStorage struct{}

// NewDummyStorage creates a new instance of DummyStorage.
func NewDummyStorage() *DummyStorage {
	return &DummyStorage{}
}

// SaveVulnerabilities logs the vulnerabilities to the console.
func (d *DummyStorage) SaveVulnerabilities(ctx context.Context, vulns []entity.Vulnerability) error {
	fmt.Printf("DummyStorage: Saved %d vulnerabilities\n", len(vulns))
	return nil
}

// QueryBySeverity returns an empty slice as it's not implemented.
func (d *DummyStorage) QueryBySeverity(ctx context.Context, severity string) ([]entity.Vulnerability, error) {
	fmt.Printf("DummyStorage: QueryBySeverity called with severity %s\n", severity)
	return []entity.Vulnerability{}, nil
}
