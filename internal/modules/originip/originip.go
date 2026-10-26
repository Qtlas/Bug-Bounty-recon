// Package originip implements origin-IP discovery. Three independent sources
// run in parallel: favUp (favicon-hash lookup via Shodan, one call per host),
// originiphunter (on the domain), and analyticsrelationships (on a host
// list). favUp is a Python script (no pip package with a stable binary), see
// config.ToolPath("favup").
//
// CDN targeting: unmasking an origin only makes sense for a host behind a
// CDN/WAF (otherwise its public IP already IS the origin). This module reads
// tech_stack.json (output of alive, field `cdn`) and restricts favUp/
// analyticsrelationships to the `cdn:true` hosts. If tech_stack.json is
// missing (alive not run, old run), it falls back to all alive hosts.
package originip

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/runner"
)

const Name = "originip"

var ipRe = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

type Module struct {
	cfg *config.Config
	run *runner.Runner
}

func New(cfg *config.Config, r *runner.Runner) *Module {
	return &Module{cfg: cfg, run: r}
}

func (m *Module) Name() string { return Name }

// DependsOn: operates on alive_subs.txt, the output of alive.
func (m *Module) DependsOn() []string { return []string{"alive"} }

func (m *Module) Run(ctx context.Context, in modules.Input) (modules.Output, error) {
	aliveSubsPath := filepath.Join(in.OutputDir, "alive_subs.txt")
	hosts := readLines(aliveSubsPath)
	if len(hosts) == 0 {
		return modules.Output{}, modules.NoInput(fmt.Sprintf("originip: %s is empty or missing (run alive first)", aliveSubsPath))
	}

	// Target the hosts behind a CDN/WAF (tech_stack.json from alive): a host
	// with no CDN has no hidden origin to find. Fall back to all alive hosts
	// if tech_stack.json is unavailable.
	targetHosts := hosts
	if cdnSet, ok := cdnFrontedHosts(in.OutputDir); ok {
		filtered := make([]string, 0, len(hosts))
		for _, h := range hosts {
			if cdnSet[strings.ToLower(h)] {
				filtered = append(filtered, h)
			}
		}
		targetHosts = filtered
		warn("tech_stack.json: %d/%d hosts behind a CDN/WAF, origin hunting targeted at those", len(filtered), len(hosts))
	} else {
		warn("tech_stack.json unavailable, origin hunting over all alive hosts (fallback)")
	}

	found := make(map[string]struct{})
	var mu sync.Mutex
	collect := func(output string) {
		mu.Lock()
		defer mu.Unlock()
		for _, ip := range ipRe.FindAllString(output, -1) {
			found[ip] = struct{}{}
		}
	}

	var g errgroup.Group
	g.Go(func() error {
		m.runFavUp(ctx, targetHosts, collect)
		return nil
	})
	g.Go(func() error {
		if in.Domain == "" {
			return nil
		}
		result, err := m.run.RunWithInput(ctx, "originiphunter", nil, in.Domain, nil)
		if err != nil {
			warn("originiphunter failed (continuing): %v", err)
			return nil
		}
		collect(result.Stdout)
		return nil
	})
	g.Go(func() error {
		// `go install` of AnalyticsRelationships produces a binary that keeps
		// the repo's casing; some forks/renames lowercase it. Take whichever
		// variant is present on PATH.
		if len(targetHosts) == 0 {
			return nil
		}
		bin, ok := runner.FirstInstalled("analyticsrelationships", "AnalyticsRelationships")
		if !ok {
			warn("analyticsrelationships not found on PATH (continuing), skipping")
			return nil
		}
		result, err := m.run.RunWithInput(ctx, bin, nil, strings.Join(targetHosts, "\n"), nil)
		if err != nil {
			warn("analyticsrelationships failed (continuing): %v", err)
			return nil
		}
		collect(result.Stdout)
		return nil
	})
	g.Wait()

	ips := make([]string, 0, len(found))
	for ip := range found {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	outPath := filepath.Join(in.OutputDir, "origin_ip_candidates.txt")
	if err := writeLines(outPath, ips); err != nil {
		return modules.Output{}, fmt.Errorf("originip: writing origin_ip_candidates.txt: %w", err)
	}

	return modules.Output{
		Files:   map[string]string{"origin_ip_candidates": outPath},
		Summary: fmt.Sprintf("%d origin IP candidates from %d CDN-fronted host(s) (%d alive)", len(ips), len(targetHosts), len(hosts)),
		Count:   len(ips),
	}, nil
}

// runFavUp runs `python3 favUp.py --web https://{host} -sc` per alive host,
// bounded by ThreadsFor(Name). Without tool_paths.favup configured or without
// api_keys.shodan_api_key, favUp is inert: warn once and skip, rather than
// failing host by host.
func (m *Module) runFavUp(ctx context.Context, hosts []string, collect func(string)) {
	scriptPath, ok := m.cfg.ToolPath("favup")
	if !ok {
		warn("tool_paths.favup not configured, skipping favUp")
		return
	}
	if m.cfg.APIKeys.ShodanAPIKey == "" {
		warn("api_keys.shodan_api_key not set, skipping favUp")
		return
	}
	env := []string{"SHODAN_API_KEY=" + m.cfg.APIKeys.ShodanAPIKey}

	threads := m.cfg.ThreadsFor(Name)
	if threads <= 0 {
		threads = 10
	}
	sem := make(chan struct{}, threads)

	var g errgroup.Group
	for _, host := range hosts {
		host := host
		g.Go(func() error {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return nil
			}
			defer func() { <-sem }()

			bin, args, _ := runner.PythonScript(scriptPath, []string{"--web", "https://" + host, "-sc"})
			result, err := m.run.RunWithEnv(ctx, bin, args, env, nil)
			if err != nil {
				warn("favUp on %s failed (continuing): %v", host, err)
				return nil
			}
			collect(result.Stdout)
			return nil
		})
	}
	g.Wait()
}

// cdnFrontedHosts reads tech_stack.json (output of alive, an array of techInfo)
// and returns the set of hosts marked cdn:true (lowercased), plus a bool
// saying whether the file could be read and parsed. ok=false => caller falls
// back.
func cdnFrontedHosts(outputDir string) (map[string]bool, bool) {
	data, err := os.ReadFile(filepath.Join(outputDir, "tech_stack.json"))
	if err != nil {
		return nil, false
	}
	var recs []struct {
		Host string `json:"host"`
		CDN  bool   `json:"cdn"`
	}
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, false
	}
	set := make(map[string]bool)
	for _, r := range recs {
		if r.CDN && r.Host != "" {
			set[strings.ToLower(r.Host)] = true
		}
	}
	return set, true
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

func warn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "originip: "+format+"\n", args...)
}
