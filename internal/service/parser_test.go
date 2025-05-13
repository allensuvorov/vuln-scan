package service

import (
	"testing"
	"time"

	"github.com/allensuvorov/vuln-scan-query/internal/domain/entity"
)

// TestParseVulnerabilities validates that the parser correctly extracts vulnerabilities
func TestParseVulnerabilities(t *testing.T) {
	// Simulate a simplified scan file (inlined instead of reading from file)
	jsonInput := []byte(`
    [
      {
        "scanResults": {
          "timestamp": "2024-05-01T12:00:00Z",
          "vulnerabilities": [
            {
              "id": "CVE-2024-1234",
              "severity": "HIGH",
              "cvss": 8.7,
              "status": "open",
              "package_name": "libfoo",
              "current_version": "1.0.0",
              "fixed_version": "1.0.1",
              "description": "A high severity vuln.",
              "published_date": "2023-12-01T08:00:00Z",
              "link": "https://example.com/cve/CVE-2024-1234",
              "risk_factors": ["Remote", "Exploit"]
            }
          ]
        }
      }
    ]
    `)

	// SourceFile and ScanTime inputs
	source := "mockfile.json"
	now := time.Now() // Not used — scan_time is parsed from JSON

	vulns, err := ParseVulnerabilities(jsonInput, source, now)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify count
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}

	got := vulns[0]
	want := entity.Vulnerability{
		ID:             "CVE-2024-1234",
		Severity:       "HIGH",
		CVSS:           8.7,
		Status:         "open",
		PackageName:    "libfoo",
		CurrentVersion: "1.0.0",
		FixedVersion:   "1.0.1",
		Description:    "A high severity vuln.",
		PublishedDate:  mustParseTime(t, "2023-12-01T08:00:00Z"),
		Link:           "https://example.com/cve/CVE-2024-1234",
		RiskFactors:    []string{"Remote", "Exploit"},
		SourceFile:     source,
		ScanTime:       mustParseTime(t, "2024-05-01T12:00:00Z"),
	}

	// Compare core fields (excluding deeply nested structs)
	if got.ID != want.ID || got.Severity != want.Severity || got.PackageName != want.PackageName {
		t.Errorf("unexpected vuln: got %+v, want %+v", got, want)
	}
}

// Test Multiple Scans in One File
func TestParseVulnerabilities_MultipleScans(t *testing.T) {
	jsonInput := []byte(`
	[
	  {
		"scanResults": {
		  "timestamp": "2024-05-01T12:00:00Z",
		  "vulnerabilities": [
			{ "id": "CVE-2024-1111", "severity": "HIGH", "cvss": 7.5, "status": "open", "package_name": "foo", "current_version": "1", "fixed_version": "2", "description": "desc", "published_date": "2023-01-01T00:00:00Z", "link": "url", "risk_factors": [] }
		  ]
		}
	  },
	  {
		"scanResults": {
		  "timestamp": "2024-05-02T12:00:00Z",
		  "vulnerabilities": [
			{ "id": "CVE-2024-2222", "severity": "LOW", "cvss": 4.0, "status": "open", "package_name": "bar", "current_version": "2", "fixed_version": "3", "description": "desc", "published_date": "2023-01-02T00:00:00Z", "link": "url", "risk_factors": [] }
		  ]
		}
	  }
	]
	`)

	vulns, err := ParseVulnerabilities(jsonInput, "source.json", time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 2 {
		t.Fatalf("expected 2 vulnerabilities, got %d", len(vulns))
	}
}

// Test Invalid JSON Format
func TestParseVulnerabilities_InvalidJSON(t *testing.T) {
	badJSON := []byte(`{ this is not valid JSON }`)

	_, err := ParseVulnerabilities(badJSON, "bad.json", time.Now())
	if err == nil {
		t.Fatal("expected error for invalid JSON, got none")
	}
}

// Test Missing Required Fields (e.g., scan timestamp)
func TestParseVulnerabilities_MissingScanTimestamp(t *testing.T) {
	jsonInput := []byte(`
	[
	  {
		"scanResults": {
		  "vulnerabilities": []
		}
	  }
	]`)

	_, err := ParseVulnerabilities(jsonInput, "bad.json", time.Now())
	if err == nil {
		t.Fatal("expected error due to missing scan_time, got none")
	}
}

// Test Invalid Published Date Format
func TestParseVulnerabilities_InvalidPublishedDate(t *testing.T) {
	jsonInput := []byte(`
	[
	  {
		"scanResults": {
		  "timestamp": "2024-05-01T12:00:00Z",
		  "vulnerabilities": [
			{
			  "id": "CVE-2024-9999",
			  "severity": "MEDIUM",
			  "cvss": 5.0,
			  "status": "open",
			  "package_name": "testpkg",
			  "current_version": "0.1.0",
			  "fixed_version": "0.1.1",
			  "description": "invalid date format",
			  "published_date": "not-a-date",
			  "link": "https://example.com",
			  "risk_factors": []
			}
		  ]
		}
	  }
	]`)

	_, err := ParseVulnerabilities(jsonInput, "bad-date.json", time.Now())
	if err == nil {
		t.Fatal("expected error due to invalid published_date, got none")
	}
}

// mustParseTime is a helper to panic on parse failure inside test code.
func mustParseTime(t *testing.T, val string) time.Time {
	ts, err := time.Parse(time.RFC3339, val)
	if err != nil {
		t.Fatalf("invalid test time: %v", err)
	}
	return ts
}
