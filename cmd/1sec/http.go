package main

// ---------------------------------------------------------------------------
// http.go — HTTP client helpers for API communication
// ---------------------------------------------------------------------------

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func apiGet(url, apiKey string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to 1SEC API at %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return body, fmt.Errorf("authentication failed (HTTP %d) — provide --api-key or set ONESEC_API_KEY", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return body, fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func apiPost(url string, payload []byte, apiKey string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to 1SEC API at %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return body, fmt.Errorf("authentication failed (HTTP %d) — provide --api-key or set ONESEC_API_KEY", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return body, fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func apiPatch(url string, payload []byte, apiKey string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to 1SEC API at %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return body, fmt.Errorf("authentication failed (HTTP %d) — provide --api-key or set ONESEC_API_KEY", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return body, fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// apiDelete sends a DELETE request.
func apiDelete(url, apiKey string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to 1SEC API at %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return body, fmt.Errorf("authentication failed (HTTP %d) — provide --api-key or set ONESEC_API_KEY", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return body, fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// isConnectionError checks if an error is a transient connection issue.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "connection reset") ||
		strings.Contains(s, "EOF") ||
		strings.Contains(s, "connection refused")
}
