# vuln-scan-query

This is a Go-based service that provides a simple API to scan vulnerability `.json` files stored in GitHub repositories and query them by severity.

It is designed to be:
- Fast and concurrent
- Cleanly layered
- Backed by SQLite with deduplication
- Packaged in a single Docker container

---

## 📦 Features

- `/scan` endpoint:
  - Accepts a repo and list of `.json` files
  - Fetches files in parallel (3 concurrent workers)
  - Parses each file on the fly
  - Saves unique vulnerabilities to SQLite
  - Retries failed GitHub fetches once

- `/query` endpoint:
  - Accepts a severity filter
  - Returns all stored vulnerabilities with matching severity

- Deduplication based on vulnerability `id` (e.g., CVE-2024-0001)

- Clean Go architecture:
  - Layered: fetcher, service, storage
  - Interfaces for testability
  - 80%+ test coverage on service layer

---

## 🧪 Testing Instructions

### ✅ Automated Tests

To run unit tests (requires Go ≥ 1.24.3):

```bash
go test ./internal/... -cover
```

### ✅ Manual Testing (via Docker)

1. Build the Docker image:

```bash
docker build -t vuln-scan-query .
```

2. Run the container:

```bash
docker run --rm -p 8080:8080 vuln-scan-query
```

3. Send a scan request:
   
```bash
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{
    "repo": "velancio/vulnerability_scans",
    "files": ["vulnscan1011.json", "vulnscan1213.json", "vulnscan15.json", "abc.json"]
  }'
```

4. Query stored results:

```bash
curl -X POST http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{"filters": {"severity": "CRITICAL"}}'
```

---

## 🛠 Tech Stack
	•	Go 1.24.x
	•	SQLite (go-sqlite3 with CGO)
	•	Docker (multi-stage)
	•	No external dependencies

---

## 🧹 Cleanup (Optional)

The SQLite DB file (vulns.db) is created inside the container and discarded on --rm. For persistence, you can mount a Docker volume.

---

## 📁 Project Structure

```
cmd/api/          # Entry point (main.go)
internal/api/     # HTTP handlers
internal/service/ # Business logic
internal/storage/ # SQLite storage
internal/githubfetcher/ # GitHub file fetcher
internal/domain/entity/ # Shared types
```
