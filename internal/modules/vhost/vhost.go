// Package vhost implements virtual-host enumeration. It fuzzes the Host header
// against the IPs discovered by infra (plus originip's candidates, best-effort
// since the two are sibling branches not guaranteed to finish together), one
// ffuf per IP in parallel (bounded by ThreadsFor), plus hosthunter (a script,
// see config.ToolPath("hosthunter")).
package vhost

import (
	"context"
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
	"github.com/Qtlas/BugBounty-recon/internal/ratelimit"
	"github.com/Qtlas/BugBounty-recon/internal/runner"
)

const Name = "vhost"

var ffufLineRe = regexp.MustCompile(`^(\S+)\s+\[Status:\s*(\d+)`)

type Module struct {
	cfg *config.Config
	run *runner.Runner
}

func New(cfg *config.Config, r *runner.Runner) *Module {
	return &Module{cfg: cfg, run: r}
}

func (m *Module) Name() string { return Name }

// DependsOn: ["alive"], like originip/urldiscovery/takeover, siblings of the
// fan-out after alive. ips_asn.txt (infra) is guaranteed ready (infra ->
// merge -> alive in the chain); origin_ip_candidates.txt (originip) is a
// bonus read best-effort only if it already exists.
func (m *Module) DependsOn() []string { return []string{"alive"} }

func (m *Module) Run(ctx context.Context, in modules.Input) (modules.Output, error) {
	if m.cfg.Wordlists.DNS == "" {
		return modules.Output{}, fmt.Errorf("vhost: wordlists.dns is required")
	}

	ips := dedupSorted(append(
		readLines(filepath.Join(in.OutputDir, "ips_asn.txt")),
		readLines(filepath.Join(in.OutputDir, "origin_ip_candidates.txt"))...,
	))
	if len(ips) == 0 {
		return modules.Output{}, modules.NoInput("vhost: no IPs found in ips_asn.txt (run infra first)")
	}

	found := make(map[string]struct{})
	var mu sync.Mutex
	collect := func(host string) {
		mu.Lock()
		found[host] = struct{}{}
		mu.Unlock()
	}

	var g errgroup.Group
	g.Go(func() error {
		m.fuzzHosts(ctx, ips, in.Domain, collect)
		return nil
	})
	g.Go(func() error {
		m.runHostHunter(ctx, ips, in.OutputDir, collect)
		return nil
	})
	g.Wait()

	vhosts := make([]string, 0, len(found))
	for h := range found {
		vhosts = append(vhosts, h)
	}
	sort.Strings(vhosts)

	outPath := filepath.Join(in.OutputDir, "vhosts_found.txt")
	if err := writeLines(outPath, vhosts); err != nil {
		return modules.Output{}, fmt.Errorf("vhost: writing vhosts_found.txt: %w", err)
	}

	return modules.Output{
		Files:   map[string]string{"vhosts_found": outPath},
		Summary: fmt.Sprintf("%d vhosts found across %d IPs", len(vhosts), len(ips)),
		Count:   len(vhosts),
	}, nil
}

// fuzzHosts runs one ffuf per IP (Host-header fuzzing), with at most
// ThreadsFor(Name) IPs in flight at once (each ffuf manages its own internal
// -t via the thread count passed as an argument). One blocking Detector per
// IP: no counter shared across concurrent processes (see internal/ratelimit,
// not thread-safe by design).
func (m *Module) fuzzHosts(ctx context.Context, ips []string, domain string, collect func(string)) {
	if domain == "" {
		return
	}
	threads := m.cfg.ThreadsFor(Name)
	if threads <= 0 {
		threads = 10
	}
	sem := make(chan struct{}, threads)

	var g errgroup.Group
	for _, ip := range ips {
		ip := ip
		g.Go(func() error {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return nil
			}
			defer func() { <-sem }()
			m.fuzzOneIP(ctx, ip, domain, collect)
			return nil
		})
	}
	g.Wait()
}

func (m *Module) fuzzOneIP(ctx context.Context, ip, domain string, collect func(string)) {
	args := []string{
		"-u", "https://" + ip,
		"-w", m.cfg.Wordlists.DNS,
		"-H", "Host: FUZZ." + domain,
		"-fs", "0",
		"-mc", "200,301,302,401,403",
		"-s",
	}
	detector := ratelimit.NewDetector(m.cfg.BlockingDetection.MaxConsecutive403, m.cfg.BlockingDetection.MaxConsecutive429, m.cfg.BlockingDetection.OnTrigger)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	_, err := m.run.Run(runCtx, "ffuf", args, func(line string) {
		match := ffufLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			return
		}
		var status int
		fmt.Sscanf(match[2], "%d", &status)
		collect(strings.ToLower(match[1]) + "." + domain + " (via " + ip + ")")

		switch detector.Observe(status) {
		case ratelimit.ActionAbort:
			warn("blocking detected on %s (status %d), aborting per blocking_detection.on_trigger=abort", ip, status)
			cancel()
		case ratelimit.ActionPauseAndReduce:
			warn("blocking detected on %s, pausing %ds", ip, m.cfg.BlockingDetection.PauseSeconds)
			// No blocking sleep here: each IP runs in its own goroutine, a
			// local sleep would only slow this branch.
		case ratelimit.ActionAlertOnly:
			warn("blocking detected on %s (alert only, continuing)", ip)
		}
	})
	if err != nil && ctx.Err() == nil {
		warn("ffuf on %s failed (continuing): %v", ip, err)
	}
}

// runHostHunter writes the merged IP list to a temporary file (hosthunter
// expects a file argument, not stdin) then runs the script
// (config.ToolPath("hosthunter")).
func (m *Module) runHostHunter(ctx context.Context, ips []string, outputDir string, collect func(string)) {
	scriptPath, ok := m.cfg.ToolPath("hosthunter")
	if !ok {
		warn("tool_paths.hosthunter not configured, skipping")
		return
	}
	ipsPath := filepath.Join(outputDir, "vhost_ips.txt")
	if err := writeLines(ipsPath, ips); err != nil {
		warn("writing vhost_ips.txt for hosthunter (continuing): %v", err)
		return
	}
	bin, args, _ := runner.PythonScript(scriptPath, []string{ipsPath})
	result, err := m.run.Run(ctx, bin, args, nil)
	if err != nil {
		warn("hosthunter failed (continuing): %v", err)
		return
	}
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			collect(line)
		}
	}
}

func dedupSorted(lines []string) []string {
	set := make(map[string]struct{}, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			set[l] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

func readLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(string(data), "\n")
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
	fmt.Fprintf(os.Stderr, "vhost: "+format+"\n", args...)
}
