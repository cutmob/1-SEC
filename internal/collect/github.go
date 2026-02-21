package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

// GitHubCollector polls GitHub Actions workflow runs and emits cicd_event and
// package_install canonical events. Requires a GitHub token with actions:read.
//
// Config:
//   type: github
//   log_path: "owner/repo"  (reused as repo identifier)
//   tag: "github"
//
// Environment:
//   GITHUB_TOKEN — personal access token or fine-grained token with actions:read
type GitHubCollector struct {
	repo     string // "owner/repo"
	tag      string
	token    string
	interval time.Duration
	cancel   context.CancelFunc
	lastSeen int64 // last workflow run ID we've processed
}

func NewGitHubCollector(repo, tag string) *GitHubCollector {
	if tag == "" {
		tag = "github"
	}
	return &GitHubCollector{
		repo:     repo,
		tag:      tag,
		interval: 60 * time.Second, // poll every 60s
	}
}

func (c *GitHubCollector) Name() string { return "github:" + c.repo }

func (c *GitHubCollector) Start(ctx context.Context, bus *core.EventBus, logger zerolog.Logger) error {
	// Get token from environment
	c.token = getEnv("GITHUB_TOKEN")
	if c.token == "" {
		return fmt.Errorf("GITHUB_TOKEN environment variable required for GitHub collector")
	}

	ctx, c.cancel = context.WithCancel(ctx)

	go func() {
		// Initial poll
		c.poll(bus, logger)

		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.poll(bus, logger)
			}
		}
	}()

	return nil
}

func (c *GitHubCollector) poll(bus *core.EventBus, logger zerolog.Logger) {
	runs, err := c.fetchWorkflowRuns()
	if err != nil {
		logger.Error().Err(err).Str("repo", c.repo).Msg("failed to fetch GitHub workflow runs")
		return
	}

	for _, run := range runs {
		runID, _ := run["id"].(float64)
		if int64(runID) <= c.lastSeen {
			continue
		}

		event := c.buildEvent(run)
		if event != nil {
			_ = bus.PublishEvent(event)
		}

		if int64(runID) > c.lastSeen {
			c.lastSeen = int64(runID)
		}
	}
}

func (c *GitHubCollector) fetchWorkflowRuns() ([]map[string]interface{}, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/runs?per_page=20", c.repo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		WorkflowRuns []map[string]interface{} `json:"workflow_runs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.WorkflowRuns, nil
}

func (c *GitHubCollector) buildEvent(run map[string]interface{}) *core.SecurityEvent {
	name, _ := run["name"].(string)
	status, _ := run["status"].(string)
	conclusion, _ := run["conclusion"].(string)
	branch, _ := run["head_branch"].(string)
	event, _ := run["event"].(string) // push, pull_request, etc.

	severity := core.SeverityInfo
	summary := fmt.Sprintf("workflow %s: %s (%s)", name, conclusion, event)

	// Flag failures
	if conclusion == "failure" {
		severity = core.SeverityMedium
		summary = fmt.Sprintf("workflow FAILED: %s on %s (%s)", name, branch, event)
	}

	// Flag suspicious triggers
	lowerEvent := strings.ToLower(event)
	if lowerEvent == "workflow_dispatch" || lowerEvent == "repository_dispatch" {
		severity = core.SeverityLow // manual/external triggers are worth noting
	}

	secEvent := core.NewSecurityEvent(c.tag, "cicd_event", severity, summary)
	secEvent.Source = "collector:" + c.tag
	secEvent.Details["action"] = conclusion
	secEvent.Details["pipeline_name"] = name
	secEvent.Details["branch"] = branch
	secEvent.Details["trigger"] = event
	secEvent.Details["status"] = status

	if actor, ok := run["actor"].(map[string]interface{}); ok {
		if login, ok := actor["login"].(string); ok {
			secEvent.Details["user"] = login
		}
	}

	if runID, ok := run["id"].(float64); ok {
		secEvent.Details["run_id"] = fmt.Sprintf("%.0f", runID)
	}

	if htmlURL, ok := run["html_url"].(string); ok {
		secEvent.Details["url"] = htmlURL
	}

	return secEvent
}

func (c *GitHubCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

// getEnv is a helper to read environment variables.
func getEnv(key string) string {
	return os.Getenv(key)
}
