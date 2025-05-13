package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3" // import the SQLite driver

	"github.com/allensuvorov/vuln-scan-query/internal/domain/entity"
)

// SQLiteStorage provides methods to store and query vulnerabilities in SQLite.
type SQLiteStorage struct {
	db *sql.DB
}

// NewSQLiteStorage opens a SQLite DB file and applies schema if needed.
func NewSQLiteStorage(dsn string) (*SQLiteStorage, error) {
	// Open the DB connection using the DSN (filename)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("cannot open db: %w", err)
	}

	// Apply schema to ensure the table exists
	err = applySchema(db)
	if err != nil {
		return nil, fmt.Errorf("cannot apply schema: %w", err)
	}

	return &SQLiteStorage{db: db}, nil
}

// applySchema creates the vulnerabilities table if it doesn't exist.
func applySchema(db *sql.DB) error {
	schema := `
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        severity TEXT,
        cvss REAL,
        status TEXT,
        package_name TEXT,
        current_version TEXT,
        fixed_version TEXT,
        description TEXT,
        published_date TEXT,
        link TEXT,
        risk_factors TEXT,
        source_file TEXT,
        scan_time TEXT
    );
    `
	_, err := db.Exec(schema)
	return err
}

// SaveVulnerabilities stores all vulnerabilities using a transaction and batch insert.
func (s *SQLiteStorage) SaveVulnerabilities(ctx context.Context, vulns []entity.Vulnerability) error {
	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	// Prepare the insert statement

	stmt, err := tx.PrepareContext(ctx, `
    INSERT OR IGNORE INTO vulnerabilities (
        id, severity, cvss, status,
        package_name, current_version, fixed_version,
        description, published_date, link, risk_factors,
        source_file, scan_time
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)

	if err != nil {
		tx.Rollback()
		return fmt.Errorf("prepare stmt: %w", err)
	}
	defer stmt.Close()

	// Insert each vulnerability
	for _, v := range vulns {
		// Encode risk factors (slice) as JSON string
		rf, err := json.Marshal(v.RiskFactors)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("encode risk factors: %w", err)
		}

		_, err = stmt.ExecContext(ctx,
			v.ID, v.Severity, v.CVSS, v.Status,
			v.PackageName, v.CurrentVersion, v.FixedVersion,
			v.Description, v.PublishedDate.Format(time.RFC3339), v.Link, string(rf),
			v.SourceFile, v.ScanTime.Format(time.RFC3339),
		)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("insert: %w", err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	fmt.Printf("✅ Saved %d vulnerabilities to DB\n", len(vulns))
	return nil
}

func (s *SQLiteStorage) QueryBySeverity(ctx context.Context, severity string) ([]entity.Vulnerability, error) {
	// Base query
	query := `SELECT 
        id, severity, cvss, status,
        package_name, current_version, fixed_version,
        description, published_date, link, risk_factors,
        source_file, scan_time
        FROM vulnerabilities`

	// Add WHERE clause if specific severity is requested
	args := []any{}
	if severity != "ALL" {
		query += " WHERE severity = ?"
		args = append(args, severity)
	}

	// Prepare and execute the query
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var results []entity.Vulnerability

	for rows.Next() {
		var v entity.Vulnerability
		var rfStr string
		var pubDateStr string
		var scanTimeStr string

		// Scan values into variables
		err := rows.Scan(
			&v.ID, &v.Severity, &v.CVSS, &v.Status,
			&v.PackageName, &v.CurrentVersion, &v.FixedVersion,
			&v.Description, &pubDateStr, &v.Link, &rfStr,
			&v.SourceFile, &scanTimeStr,
		)
		if err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}

		// Parse dates
		v.PublishedDate, err = time.Parse(time.RFC3339, pubDateStr)
		if err != nil {
			return nil, fmt.Errorf("invalid published_date: %w", err)
		}
		v.ScanTime, err = time.Parse(time.RFC3339, scanTimeStr)
		if err != nil {
			return nil, fmt.Errorf("invalid scan_time: %w", err)
		}

		// Decode JSON-encoded risk_factors
		err = json.Unmarshal([]byte(rfStr), &v.RiskFactors)
		if err != nil {
			return nil, fmt.Errorf("unmarshal risk_factors: %w", err)
		}

		results = append(results, v)
	}

	// Check for row scan errors
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows err: %w", err)
	}

	fmt.Printf("✅ Fetched %d vulnerabilities with severity %s\n", len(results), severity)
	return results, nil
}
