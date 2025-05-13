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