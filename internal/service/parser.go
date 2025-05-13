package service

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/allensuvorov/vuln-scan-query/internal/domain/entity"
)

// ParseVulnerabilities parses the JSON data from a vulnerability scan file.
// It extracts vulnerabilities and enriches them with metadata such as source file and scan time.
func ParseVulnerabilities(data []byte, sourceFile string, _ time.Time) ([]entity.Vulnerability, error) {
	// Define structures to match the structure of each scan item.
	type RawVuln struct {
		ID             string   `json:"id"`
		Severity       string   `json:"severity"`
		CVSS           float64  `json:"cvss"`
		Status         string   `json:"status"`
		PackageName    string   `json:"package_name"`
		CurrentVersion string   `json:"current_version"`
		FixedVersion   string   `json:"fixed_version"`
		Description    string   `json:"description"`
		PublishedDate  string   `json:"published_date"`
		Link           string   `json:"link"`
		RiskFactors    []string `json:"risk_factors"`
	}

	type RawScanResults struct {
		Timestamp       string    `json:"timestamp"`
		Vulnerabilities []RawVuln `json:"vulnerabilities"`
	}

	type RawScanWrapper struct {
		ScanResults RawScanResults `json:"scanResults"`
	}

	// The root of the JSON is an array of RawScanWrapper.
	var scanWrappers []RawScanWrapper
	if err := json.Unmarshal(data, &scanWrappers); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	var results []entity.Vulnerability

	for _, wrapper := range scanWrappers {
		scan := wrapper.ScanResults
		scanTime, err := time.Parse(time.RFC3339, scan.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp format: %w", err)
		}

		for _, v := range scan.Vulnerabilities {
			publishedDate, err := time.Parse(time.RFC3339, v.PublishedDate)
			if err != nil {
				return nil, fmt.Errorf("invalid published_date format: %w", err)
			}

			vuln := entity.Vulnerability{
				ID:             v.ID,
				Severity:       v.Severity,
				CVSS:           v.CVSS,
				Status:         v.Status,
				PackageName:    v.PackageName,
				CurrentVersion: v.CurrentVersion,
				FixedVersion:   v.FixedVersion,
				Description:    v.Description,
				PublishedDate:  publishedDate,
				Link:           v.Link,
				RiskFactors:    v.RiskFactors,
				SourceFile:     sourceFile,
				ScanTime:       scanTime,
			}

			results = append(results, vuln)
		}
	}

	fmt.Printf("Parsed %d vulnerabilities from %s\n", len(results), sourceFile)
	return results, nil
}
