// Package alive implements liveness detection plus combined technology
// fingerprinting. It is the central hub of the dependency graph: httpx first
// determines which hosts of all_subs.txt are alive (alive_subs.txt), then
// whatweb/webanalyze/gowitness run in parallel over that same alive_subs.txt,
// merged into tech_stack.json.
package alive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/runner"
)

const Name = "alive"

type Module struct {
	cfg *config.Config
	run *runner.Runner
}

func New(cfg *config.Config, r *runner.Runner) *Module {
	return &Module{cfg: cfg, run: r}
}

func (m *Module) Name() string { return Name }

// DependsOn: consumes all_subs.txt, the output of merge_resolve.
func (m *Module) DependsOn() []string { return []string{"merge_resolve"} }

// techInfo is the per-host JSON object, merging httpx (-td), whatweb (-a 3)
// and webanalyze.
type techInfo struct {
	Host       string   `json:"host"`
	StatusCode int      `json:"status_code,omitempty"`
	Title      string   `json:"title,omitempty"`
	Server     string   `json:"server,omitempty"`
	Tech       []string `json:"tech,omitempty"`
	// CDN/WAF detected by httpx: directly useful to the origin-IP module to
	// target the hosts worth "unmasking" (behind a CDN).
	CDN     bool   `json:"cdn,omitempty"`
	CDNName string `json:"cdn_name,omitempty"`
	CDNType string `json:"cdn_type,omitempty"`
	// Resolved IPs (A + AAAA) reported by httpx, useful to vhost/portscan.
	IPs        []string `json:"ips,omitempty"`
	WhatwebRaw string   `json:"whatweb_raw,omitempty"`
}

func (m *Module) Run(ctx context.Context, in modules.Input) (modules.Output, error) {
	allSubsPath := filepath.Join(in.OutputDir, "all_subs.txt")
	hosts := readLines(allSubsPath)
	if len(hosts) == 0 {
		return modules.Output{}, modules.NoInput(fmt.Sprintf("alive: %s is empty or missing (run merge_resolve first)", allSubsPath))
	}

	aliveHosts, enrichedLines, tech := m.probeHTTPX(ctx, hosts)
	sort.Strings(aliveHosts)

	aliveSubsPath := filepath.Join(in.OutputDir, "alive_subs.txt")
	enrichedPath := filepath.Join(in.OutputDir, "alive_enriched.txt")
	techPath := filepath.Join(in.OutputDir, "tech_stack.json")
	screenshotsDir := filepath.Join(in.OutputDir, "screenshots")

	if err := writeLines(aliveSubsPath, aliveHosts); err != nil {
		return modules.Output{}, fmt.Errorf("alive: writing alive_subs.txt: %w", err)
	}
	if err := writeLines(enrichedPath, enrichedLines); err != nil {
		return modules.Output{}, fmt.Errorf("alive: writing alive_enriched.txt: %w", err)
	}

	// whatweb, webanalyze and gowitness all consume alive_subs.txt and are
	// independent: run in parallel. whatweb and webanalyze both merge into the
	// shared `tech` map, so a mutex guards that map (gowitness does not touch
	// it).
	if len(aliveHosts) > 0 {
		var techMu sync.Mutex
		var g errgroup.Group
		g.Go(func() error {
			m.runWhatweb(ctx, aliveSubsPath, in.OutputDir, tech, &techMu)
			return nil
		})
		g.Go(func() error {
			m.runWebanalyze(ctx, aliveSubsPath, in.OutputDir, tech, &techMu)
			return nil
		})
		g.Go(func() error {
			m.runGowitness(ctx, aliveSubsPath, screenshotsDir)
			return nil
		})
		g.Wait()
	}

	techList := make([]*techInfo, 0, len(tech))
	for _, t := range tech {
		techList = append(techList, t)
	}
	sort.Slice(techList, func(i, j int) bool { return techList[i].Host < techList[j].Host })
	if err := writeJSON(techPath, techList); err != nil {
		return modules.Output{}, fmt.Errorf("alive: writing tech_stack.json: %w", err)
	}

	return modules.Output{
		Files: map[string]string{
			"alive_subs":     aliveSubsPath,
			"alive_enriched": enrichedPath,
			"tech_stack":     techPath,
			"screenshots":    screenshotsDir,
		},
		Summary: fmt.Sprintf("%d/%d hosts alive, tech fingerprinted for %d", len(aliveHosts), len(hosts), len(techList)),
		Count:   len(aliveHosts),
	}, nil
}

// httpxRecord models the fields we care about in a line of `httpx -json`.
// Fields are not guaranteed across httpx versions, tolerated absent.
type httpxRecord struct {
	Input      string   `json:"input"`
	URL        string   `json:"url"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	Webserver  string   `json:"webserver"`
	Tech       []string `json:"tech"`
	CDN        bool     `json:"cdn"`
	CDNName    string   `json:"cdn_name"`
	CDNType    string   `json:"cdn_type"`
	A          []string `json:"a"`    // resolved IPv4
	AAAA       []string `json:"aaaa"` // resolved IPv6
}

// isPythonHTTPX recognizes the error signature of the Python httpx library's
// CLI (click), served instead of ProjectDiscovery's httpx when both are
// installed and the wrong one comes first on PATH.
func isPythonHTTPX(stderr string) bool {
	return strings.Contains(stderr, "Usage: httpx [OPTIONS]") || strings.Contains(stderr, "No such option")
}

// probeHTTPX pipes all hosts into a single httpx call (instead of one per
// host), capturing the JSON line by line rather than relying on httpx's text
// format, to produce alive_subs.txt/alive_enriched.txt in a stable format we
// control.
func (m *Module) probeHTTPX(ctx context.Context, hosts []string) ([]string, []string, map[string]*techInfo) {
	tech := make(map[string]*techInfo)
	args := []string{
		"-status-code", "-content-length", "-web-server", "-title",
		"-follow-redirects", "-td", "-json", "-silent",
	}
	result, err := m.run.RunWithInput(ctx, "httpx", args, strings.Join(hosts, "\n"), nil)
	if err != nil {
		if result != nil && isPythonHTTPX(result.Stderr) {
			// Classic collision: the `httpx` on PATH is the Python httpx
			// library's CLI, not ProjectDiscovery's. Our flags are correct for
			// PD; the Python CLI rejects them. Say so clearly rather than let
			// the cryptic error through.
			warn("the `httpx` on PATH looks like the Python httpx library, not ProjectDiscovery's. " +
				"Install it with `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` " +
				"and make sure $(go env GOPATH)/bin comes before ~/.local/bin on your PATH.")
		} else {
			warn("httpx failed (continuing): %v", err)
		}
	}
	if result == nil {
		return nil, nil, tech
	}

	var alive []string
	var enriched []string
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec httpxRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		host := hostOf(rec.Input, rec.URL)
		if host == "" {
			continue
		}
		alive = append(alive, host)
		enriched = append(enriched, fmt.Sprintf("%s [%d] server=%q title=%q", host, rec.StatusCode, rec.Webserver, rec.Title))
		ips := append(append([]string{}, rec.A...), rec.AAAA...)
		tech[host] = &techInfo{
			Host: host, StatusCode: rec.StatusCode, Title: rec.Title, Server: rec.Webserver, Tech: rec.Tech,
			CDN: rec.CDN, CDNName: rec.CDNName, CDNType: rec.CDNType, IPs: ips,
		}
	}
	return alive, enriched, tech
}

// runWhatweb writes its own file via --log-brief, then we re-read it to merge
// into tech (best-effort: whatweb's "brief" format is free text, we keep the
// raw line per host rather than parsing it finely). The merge into the shared
// map is guarded by mu.
func (m *Module) runWhatweb(ctx context.Context, aliveSubsPath, outputDir string, tech map[string]*techInfo, mu *sync.Mutex) {
	logPath := filepath.Join(outputDir, "whatweb_results.txt")
	args := []string{"-i", aliveSubsPath, "-a", "3", "-t", fmt.Sprintf("%d", m.cfg.ThreadsFor(Name)), "--log-brief=" + logPath}
	if _, err := m.run.Run(ctx, "whatweb", args, nil); err != nil {
		warn("whatweb failed (continuing): %v", err)
	}
	parsed := parseWhatweb(readLines(logPath))
	mu.Lock()
	defer mu.Unlock()
	for host, raw := range parsed {
		t, ok := tech[host]
		if !ok {
			t = &techInfo{Host: host}
			tech[host] = t
		}
		t.WhatwebRaw = raw
	}
}

// parseWhatweb associates each host with the most informative `whatweb
// --log-brief` line. whatweb emits several per host (http/https, 301 then
// 200, with/without trailing slash): we keep the longest, the one carrying
// the most plugins (the final 200 rather than a 301 redirect). Each line is
// "`<url> [<status>] Plugin[..], Plugin2[..], ...`", hence the host taken from
// the first field.
func parseWhatweb(lines []string) map[string]string {
	out := map[string]string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		host := hostOf(strings.SplitN(line, " ", 2)[0])
		if host == "" {
			continue
		}
		if len(line) > len(out[host]) {
			out[host] = line
		}
	}
	return out
}

// webanalyzeResult models `webanalyze -output json` (one object per host).
type webanalyzeResult struct {
	Hostname string `json:"hostname"`
	Matches  []struct {
		AppName string `json:"app_name"`
	} `json:"matches"`
}

func (m *Module) runWebanalyze(ctx context.Context, aliveSubsPath, outputDir string, tech map[string]*techInfo, mu *sync.Mutex) {
	args := []string{"-hosts", aliveSubsPath, "-output", "json"}
	// By default webanalyze looks for technologies.json in the CWD, which makes
	// the binary non-portable. If tool_paths.webanalyze_apps is set (absolute
	// path, resolved by config), pass it via -apps so it no longer depends on
	// the launch directory.
	if apps, ok := m.cfg.ToolPath("webanalyze_apps"); ok {
		args = append(args, "-apps", apps)
	}
	result, err := m.run.Run(ctx, "webanalyze", args, nil)
	if err != nil {
		warn("webanalyze failed (continuing): %v", err)
		return
	}
	resultPath := filepath.Join(outputDir, "webanalyze_results.json")
	if err := os.WriteFile(resultPath, []byte(result.Stdout), 0o644); err != nil {
		warn("writing webanalyze_results.json (continuing): %v", err)
	}

	parsed := parseWebanalyze(result.Stdout)
	mu.Lock()
	defer mu.Unlock()
	for _, rec := range parsed {
		host := hostOf(rec.Hostname)
		if host == "" {
			continue
		}
		t, ok := tech[host]
		if !ok {
			t = &techInfo{Host: host}
			tech[host] = t
		}
		for _, match := range rec.Matches {
			t.Tech = appendUnique(t.Tech, match.AppName)
		}
	}
}

// parseWebanalyze reads the output of `webanalyze -output json`, which is
// JSONL (one object per host per line), preceded by a banner (`:: webanalyze
// …`): definitely NOT a global JSON array. We parse line by line and ignore
// any line that is not a JSON object (banner, blank lines), as for httpx.
func parseWebanalyze(stdout string) []webanalyzeResult {
	var out []webanalyzeResult
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec webanalyzeResult
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out
}

func (m *Module) runGowitness(ctx context.Context, aliveSubsPath, screenshotsDir string) {
	if err := os.MkdirAll(screenshotsDir, 0o755); err != nil {
		warn("creating screenshots dir (continuing): %v", err)
		return
	}
	args := []string{"file", "-f", aliveSubsPath, "-P", screenshotsDir, "--no-http"}
	if _, err := m.run.Run(ctx, "gowitness", args, nil); err != nil {
		warn("gowitness failed (continuing): %v", err)
	}
}

// hostOf returns the first non-empty candidate, without scheme/port/trailing
// slash, to normalize the keys used across httpx/whatweb/webanalyze (which do
// not necessarily output the same format for a given host).
func hostOf(candidates ...string) string {
	for _, raw := range candidates {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			return strings.ToLower(u.Hostname())
		}
		return strings.ToLower(strings.TrimSuffix(raw, "/"))
	}
	return ""
}

func appendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, existing := range list {
		if existing == v {
			return list
		}
	}
	return append(list, v)
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
	fmt.Fprintf(os.Stderr, "alive: "+format+"\n", args...)
}
