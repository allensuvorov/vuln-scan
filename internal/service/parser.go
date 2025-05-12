package service

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/allensuvorov/vuln-scan-query/internal/domain/entity"
)

func ParseVulnerabilities(data []byte, sourceFile string, scanTime time.Time) ([]entity.Vulnerability, error) {
	var parsed []entity.Vulnerability
	err := json.Unmarshal(data, &parsed)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON array: %w", err)
	}

	for i := range parsed {
		parsed[i].SourceFile = sourceFile
		parsed[i].ScanTime = scanTime
	}

	return parsed, nil
}
