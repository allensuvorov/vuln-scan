package githubfetcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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
		// Construct the API URL for the file.
		url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repoName, file)

		// Create a new HTTP GET request with the provided context.
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		// Set the Accept header to receive JSON response.
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		// Execute the HTTP request.
		resp, err := g.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch file %s: %w", file, err)
		}
		defer resp.Body.Close()

		// Check for non-200 HTTP status codes.
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("GitHub API error for file %s: %s", file, string(body))
		}

		// Parse the JSON response.
		var content struct {
			Content  string `json:"content"`
			Encoding string `json:"encoding"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&content); err != nil {
			return nil, fmt.Errorf("failed to decode response for file %s: %w", file, err)
		}

		// Decode the base64-encoded content.
		if content.Encoding != "base64" {
			return nil, fmt.Errorf("unexpected encoding for file %s: %s", file, content.Encoding)
		}
		decoded, err := base64.StdEncoding.DecodeString(content.Content)
		if err != nil {
			return nil, fmt.Errorf("failed to decode content for file %s: %w", file, err)
		}

		// Store the decoded content in the result map.
		result[file] = decoded
	}

	// Log for testing
	// for k, v := range result {
	// 	log.Print(k, string(v))
	// }

	return result, nil
}
