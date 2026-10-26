// Package dirbrute implements directory bruteforce and sensitive-file
// discovery. Three independent branches run in parallel: dirsearch (or
// feroxbuster if modules.fast_dirbrute), a grep over waybackurls for
// sensitive files, and bfac per host.
package dirbrute

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/runner"
)

const Name = "dirbrute"

var sensitiveExtRe = regexp.MustCompile(`(?i)\.(sql|bak|env|pem|key|git|log|DS_Store)(\?|$)`)

type Module struct {
	cfg *config.Config
	run *runner.Runner
}

func New(cfg *config.Config, r *runner.Runner) *Module {
	return &Module{cfg: cfg, run: r}
}

func (m *Module) Name() string { return Name }

// DependsOn: consumes alive_subs.txt, the output of alive.
func (m *Module) DependsOn() []string { return []string{"alive"} }

func (m *Module) Run(ctx context.Context, in modules.Input) (modules.Output, error) {
	if m.cfg.Wordlists.Web == "" {
		return modules.Output{}, fmt.Errorf("dirbrute: wordlists.web is required")
	}
	aliveSubsPath := filepath.Join(in.OutputDir, "alive_subs.txt")
	hosts := readLines(aliveSubsPath)
	if len(hosts) == 0 {
		return modules.Output{}, modules.NoInput(fmt.Sprintf("dirbrute: %s is empty or missing (run alive first)", aliveSubsPath))
	}

	dirsearchPath := filepath.Join(in.OutputDir, "dirsearch_all.txt")
	sensitivePath := filepath.Join(in.OutputDir, "sensitive_wayback.txt")
	bfacPath := filepath.Join(in.OutputDir, "bfac_results.txt")

	var g errgroup.Group
	g.Go(func() error { m.runDirBrute(ctx, aliveSubsPath, hosts, dirsearchPath); return nil })
	g.Go(func() error { m.runSensitiveWayback(ctx, in.Domain, sensitivePath); return nil })
	g.Go(func() error { m.runBfac(ctx, hosts, bfacPath); return nil })
	g.Wait()

	return modules.Output{
		Files: map[string]string{
			"dirsearch_all":     dirsearchPath,
			"sensitive_wayback": sensitivePath,
			"bfac_results":      bfacPath,
		},
		Summary: fmt.Sprintf("dir bruteforce + sensitive files check over %d hosts (fast_dirbrute=%v)", len(hosts), m.cfg.Modules.FastDirbrute),
	}, nil
}

// runDirBrute uses feroxbuster per host if modules.fast_dirbrute is set,
// dirsearch over the whole list otherwise (the default).
func (m *Module) runDirBrute(ctx context.Context, aliveSubsPath string, hosts []string, outPath string) {
	if !m.cfg.Modules.FastDirbrute {
		args := []string{"-l", aliveSubsPath, "--full-url", "-e", "php,env,json,yaml,bak,zip,sql,conf", "-o", outPath}
		if _, err := m.run.Run(ctx, "dirsearch", args, nil); err != nil {
			warn("dirsearch failed (continuing): %v", err)
		}
		return
	}

	threads := m.cfg.ThreadsFor(Name)
	if threads <= 0 {
		threads = 10
	}
	sem := make(chan struct{}, threads)
	var lines []string
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
			args := []string{
				"-u", "https://" + host, "-w", m.cfg.Wordlists.Web, "-t", "300", "-k", "-d", "3",
				"-x", "php,html,json,js,log,txt,bak,old,zip,tar,gz", "-q",
			}
			result, err := m.run.Run(ctx, "feroxbuster", args, nil)
			if err != nil {
				warn("feroxbuster on %s failed (continuing): %v", host, err)
				return nil
			}
			lines = append(lines, splitNonEmpty(result.Stdout)...)
			return nil
		})
	}
	g.Wait()
	if err := writeLines(outPath, lines); err != nil {
		warn("writing dirsearch_all.txt (continuing): %v", err)
	}
}

func (m *Module) runSensitiveWayback(ctx context.Context, domain, outPath string) {
	if domain == "" {
		return
	}
	result, err := m.run.Run(ctx, "waybackurls", []string{domain}, nil)
	if err != nil {
		warn("waybackurls failed (continuing): %v", err)
		return
	}
	found := make(map[string]struct{})
	for _, line := range splitNonEmpty(result.Stdout) {
		if sensitiveExtRe.MatchString(line) {
			found[line] = struct{}{}
		}
	}
	lines := make([]string, 0, len(found))
	for l := range found {
		lines = append(lines, l)
	}
	sort.Strings(lines)
	if err := writeLines(outPath, lines); err != nil {
		warn("writing sensitive_wayback.txt (continuing): %v", err)
	}
}

func (m *Module) runBfac(ctx context.Context, hosts []string, outPath string) {
	threads := m.cfg.ThreadsFor(Name)
	if threads <= 0 {
		threads = 10
	}
	sem := make(chan struct{}, threads)
	var lines []string
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
			args := []string{"--url", "https://" + host, "--detection-technique", "all", "--exclude-status-codes", "404,500"}
			result, err := m.run.Run(ctx, "bfac", args, nil)
			if err != nil {
				warn("bfac on %s failed (continuing): %v", host, err)
				return nil
			}
			if out := strings.TrimSpace(result.Stdout); out != "" {
				lines = append(lines, "== "+host+" ==")
				lines = append(lines, splitNonEmpty(out)...)
			}
			return nil
		})
	}
	g.Wait()
	if err := writeLines(outPath, lines); err != nil {
		warn("writing bfac_results.txt (continuing): %v", err)
	}
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func readLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return splitNonEmpty(string(data))
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
	fmt.Fprintf(os.Stderr, "dirbrute: "+format+"\n", args...)
}
