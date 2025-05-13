package storage

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3" // import the SQLite driver
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
        id TEXT,
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
