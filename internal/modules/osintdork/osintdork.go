// Package osintdork implements search-engine dorking. It issues direct HTTP
// requests to DuckDuckGo's HTML endpoint (no JS rendering needed, no captcha
// in reasonable use), which covers the goal (public indexing of sensitive
// content) with a far lower blocking risk than scripting a full browser
// against Google. Known limitation: less exhaustive than a real Google
// engine.
package osintdork

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/runner"
)

const Name = "osintdork"

// maxConcurrentQueries stays deliberately low: hammering a search engine is
// the shortest path to a block, unlike bruteforcing the target's own
// infrastructure where we control the pace via rate_limits.
const maxConcurrentQueries = 2

type dorkResult struct {
	Query    string   `json:"query"`
	Category string   `json:"category"`
	URLs     []string `json:"urls"`
}

type Module struct {
	cfg *config.Config
	run *runner.Runner
}

func New(cfg *config.Config, r *runner.Runner) *Module {
	return &Module{cfg: cfg, run: r}
}

func (m *Module) Name() string { return Name }

// DependsOn: the contextual dorks need the URL categories from urldiscovery
// and the fingerprint from alive (tech_stack.json). The generic dorks do not,
// but run in the same module, no reason to split.
func (m *Module) DependsOn() []string { return []string{"urldiscovery", "alive"} }

func (m *Module) Run(ctx context.Context, in modules.Input) (modules.Output, error) {
	if in.Domain == "" {
		return modules.Output{}, fmt.Errorf("osintdork: domain is required")
	}

	dorks := genericDorks(in.Domain)
	dorks = append(dorks, contextualDorks(in.Domain, in.OutputDir)...)

	results := make([]dorkResult, 0, len(dorks))
	sem := make(chan struct{}, maxConcurrentQueries)
	resultsCh := make(chan dorkResult, len(dorks))
	for _, d := range dorks {
		d := d
		go func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			urls := m.searchDuckDuckGo(ctx, d.Query)
			resultsCh <- dorkResult{Query: d.Query, Category: d.Category, URLs: urls}
			// Polite pause between two search queries: unlike bruteforcing the
			// target's infrastructure, here we query a third party (DuckDuckGo)
			// we do not want to hit in bursts.
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
			}
		}()
	}
	for range dorks {
		results = append(results, <-resultsCh)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Query < results[j].Query })

	exposed := make(map[string]struct{})
	for _, r := range results {
		for _, u := range r.URLs {
			exposed[u] = struct{}{}
		}
	}
	exposedList := make([]string, 0, len(exposed))
	for u := range exposed {
		exposedList = append(exposedList, u)
	}
	sort.Strings(exposedList)

	dorksPath := filepath.Join(in.OutputDir, "dorks_results.json")
	exposedPath := filepath.Join(in.OutputDir, "exposed_indexed_urls.txt")
	if err := writeJSON(dorksPath, results); err != nil {
		return modules.Output{}, fmt.Errorf("osintdork: writing dorks_results.json: %w", err)
	}
	if err := writeLines(exposedPath, exposedList); err != nil {
		return modules.Output{}, fmt.Errorf("osintdork: writing exposed_indexed_urls.txt: %w", err)
	}

	return modules.Output{
		Files: map[string]string{
			"dorks_results":        dorksPath,
			"exposed_indexed_urls": exposedPath,
		},
		Summary: fmt.Sprintf("%d dorks run, %d indexed URLs found", len(dorks), len(exposedList)),
		Count:   len(exposedList),
	}, nil
}

type dork struct {
	Query    string
	Category string
}

// genericDorks does not depend on the context from alive/urldiscovery: a leak
// of internal Google Sheets is worth checking by default on any target.
func genericDorks(domain string) []dork {
	return []dork{
		{Query: fmt.Sprintf(`site:docs.google.com/spreadsheets "%s"`, domain), Category: "google_sheets_leak"},
		{Query: fmt.Sprintf(`site:docs.google.com/spreadsheets "@%s"`, domain), Category: "google_sheets_leak"},
	}
}

// contextualDorks derives dorks from what urldiscovery already observed: a
// path prefix seen in idor_candidates.txt/admin_urls.txt becomes an `inurl:`
// dork to check for indexing (e.g. `/user/order/{id}` -> `inurl:/user/order`).
func contextualDorks(domain, outputDir string) []dork {
	var dorks []dork
	seen := make(map[string]struct{})
	for _, file := range []string{"idor_candidates.txt", "admin_urls.txt"} {
		for _, u := range readLines(filepath.Join(outputDir, file)) {
			prefix := pathPrefix(u)
			if prefix == "" || prefix == "/" {
				continue
			}
			if _, dup := seen[prefix]; dup {
				continue
			}
			seen[prefix] = struct{}{}
			dorks = append(dorks, dork{
				Query:    fmt.Sprintf(`site:%s inurl:%s`, domain, prefix),
				Category: "contextual",
			})
		}
	}
	return dorks
}

// pathPrefix keeps the first two path segments of a URL (e.g.
// "/user/order/42" -> "/user/order").
func pathPrefix(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segments) == 0 || segments[0] == "" {
		return ""
	}
	if len(segments) == 1 {
		return "/" + segments[0]
	}
	return "/" + segments[0] + "/" + segments[1]
}

var ddgResultLinkRe = regexp.MustCompile(`uddg=([^&"]+)`)

// searchDuckDuckGo queries DuckDuckGo's HTML endpoint (no JS rendering
// required) and extracts the target URLs from the result links (the uddg
// parameter, see ddgResultLinkRe).
func (m *Module) searchDuckDuckGo(ctx context.Context, query string) []string {
	endpoint := "https://html.duckduckgo.com/html/?q=" + url.QueryEscape(query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon-mcp/1.0)")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		warn("DuckDuckGo query failed (continuing): %v", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		warn("DuckDuckGo returned HTTP %d for query %q (continuing)", resp.StatusCode, query)
		return nil
	}

	body := make([]byte, 0, 64*1024)
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if readErr != nil {
			break
		}
	}

	found := make(map[string]struct{})
	for _, match := range ddgResultLinkRe.FindAllStringSubmatch(string(body), -1) {
		target, err := url.QueryUnescape(match[1])
		if err == nil && target != "" {
			found[target] = struct{}{}
		}
	}
	urls := make([]string, 0, len(found))
	for u := range found {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	return urls
}

func readLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func warn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "osintdork: "+format+"\n", args...)
}
