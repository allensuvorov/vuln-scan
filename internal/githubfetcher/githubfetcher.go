package githubfetcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GitHubFetcher is responsible for fetching files from GitHub repositories.
type GitHubFetcher struct {
	client *http.Client
}

// New creates a new instance of GitHubFetcher with the provided HTTP client.
func New(client *http.Client) *GitHubFetcher {
	return &GitHubFetcher{client: client}
}

// FetchFiles retrieves the contents of specified files from a GitHub repository.
func (g *GitHubFetcher) FetchFiles(ctx context.Context, repo string, files []string) (map[string][]byte, error) {
	// Split the repo string into owner and repository name.
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repo format: %s", repo)
	}
	owner, repoName := parts[0], parts[1]

	// Initialize a map to store file contents.
	result := make(map[string][]byte)

	// Iterate over each file to fetch its content.
	for _, file := range files {
		var (
			data []byte
			err  error
		)

		// Retry loop: 2 attempts (initial + 1 retry)
		for attempt := 1; attempt <= 2; attempt++ {
			data, err = g.fetchFile(ctx, owner, repoName, file)
			if err == nil {
				break // success
			}

			fmt.Printf("⚠️  Attempt %d failed for %s: %v\n", attempt, file, err)
			time.Sleep(300 * time.Millisecond) // small delay before retry
		}

		if err != nil {
			return nil, fmt.Errorf("failed to fetch %s after retries: %w", file, err)
		}

		result[file] = data
	}

	return result, nil
}

func (g *GitHubFetcher) fetchFile(ctx context.Context, owner, repo, file string) ([]byte, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, file)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var content struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&content); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if content.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected encoding: %s", content.Encoding)
	}

	decoded, err := base64.StdEncoding.DecodeString(content.Content)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}

	return decoded, nil
}
