package service

import (
	"context"
	"testing"

	"github.com/allensuvorov/vuln-scan-query/internal/domain/entity"
)

// Test service.Query()
func TestQuery_MissingSeverity(t *testing.T) {
	svc := New(nil, nil) // no fetcher or storage needed for this test

	_, err := svc.Query(context.Background(), entity.QueryRequest{
		Filters: map[string]string{},
	})
	if err == nil {
		t.Fatal("expected error due to missing severity, got none")
	}
}

// Test service.Scan() (with Mocks)
type mockFetcher struct {
	files map[string][]byte
}

func (m *mockFetcher) FetchFiles(ctx context.Context, repo string, files []string) (map[string][]byte, error) {
	result := make(map[string][]byte)
	for _, f := range files {
		if data, ok := m.files[f]; ok {
			result[f] = data
		}
	}
	return result, nil
}

type mockStorage struct {
	saved []entity.Vulnerability
}

func (m *mockStorage) SaveVulnerabilities(ctx context.Context, vulns []entity.Vulnerability) error {
	m.saved = vulns
	return nil
}

func (m *mockStorage) QueryBySeverity(ctx context.Context, severity string) ([]entity.Vulnerability, error) {
	return nil, nil
}

func TestScan_Success(t *testing.T) {
	fetcher := &mockFetcher{
		files: map[string][]byte{
			"file1.json": []byte(`
			[
			  {
				"scanResults": {
				  "timestamp": "2024-05-01T12:00:00Z",
				  "vulnerabilities": [
					{
					  "id": "CVE-9999-0001",
					  "severity": "HIGH",
					  "cvss": 9.1,
					  "status": "open",
					  "package_name": "demo",
					  "current_version": "1",
					  "fixed_version": "2",
					  "description": "test",
					  "published_date": "2023-01-01T00:00:00Z",
					  "link": "https://example.com",
					  "risk_factors": ["Remote"]
					}
				  ]
				}
			  }
			]`),
		},
	}

	storage := &mockStorage{}

	svc := New(fetcher, storage)

	err := svc.Scan(context.Background(), entity.ScanRequest{
		Repo:  "user/repo",
		Files: []string{"file1.json"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(storage.saved) != 1 {
		t.Fatalf("expected 1 vulnerability saved, got %d", len(storage.saved))
	}
}
