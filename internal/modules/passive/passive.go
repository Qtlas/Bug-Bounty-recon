// Package passive implements passive subdomain enumeration. No active request
// to the target: crt.sh (direct HTTP), subfinder, assetfinder, findomain, and
// amass as an option (modules.deep_passive, since it is slow).
package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/runner"
)

const Name = "passive"

type Module struct {
	cfg *config.Config
	run *runner.Runner
}

func New(cfg *config.Config, r *runner.Runner) *Module {
	return &Module{cfg: cfg, run: r}
}

func (m *Module) Name() string { return Name }

// DependsOn returns nil: this is an entry point of the pipeline, purely
// passive, with no dependency on another module.
func (m *Module) DependsOn() []string { return nil }

func (m *Module) Run(ctx context.Context, in modules.Input) (modules.Output, error) {
	if in.Domain == "" {
		return modules.Output{}, fmt.Errorf("passive: domain is required")
	}

	// The 4-5 sources are independent (none consumes another's output), run in
	// parallel rather than in sequence: the module's total time becomes the
	// slowest source's, not their sum. Each goroutine writes into its own
	// local map (no mutex needed); merging into `found` happens after
	// g.Wait().
	type source struct {
		name string
		fn   func(into map[string]struct{}) error
	}
	sources := []source{
		{"crt.sh", func(into map[string]struct{}) error { return queryCrtSh(ctx, in.Domain, into) }},
		{"subfinder", func(into map[string]struct{}) error {
			return m.runToolLines(ctx, "subfinder", []string{"-d", in.Domain, "-silent"}, into)
		}},
		{"assetfinder", func(into map[string]struct{}) error {
			return m.runToolLines(ctx, "assetfinder", []string{"--subs-only", in.Domain}, into)
		}},
		{"findomain", func(into map[string]struct{}) error {
			return m.runToolLines(ctx, "findomain", []string{"-t", in.Domain, "-q"}, into)
		}},
	}
	// amass: only if modules.deep_passive is set, notoriously slow, out of the
	// default run.
	if m.cfg.Modules.DeepPassive {
		sources = append(sources, source{"amass", func(into map[string]struct{}) error {
			return m.runToolLines(ctx, "amass", []string{"enum", "-passive", "-d", in.Domain}, into)
		}})
	}

	results := make([]map[string]struct{}, len(sources))
	var g errgroup.Group
	for i, src := range sources {
		i, src := i, src
		g.Go(func() error {
			local := make(map[string]struct{})
			if err := src.fn(local); err != nil {
				warn("%s failed (continuing): %v", src.name, err)
			}
			results[i] = local
			return nil
		})
	}
	g.Wait()

	found := make(map[string]struct{})
	for _, local := range results {
		for s := range local {
			found[s] = struct{}{}
		}
	}

	subs := make([]string, 0, len(found))
	for s := range found {
		subs = append(subs, s)
	}
	sort.Strings(subs)

	outPath := filepath.Join(in.OutputDir, "subs_passive.txt")
	if err := writeLines(outPath, subs); err != nil {
		return modules.Output{}, fmt.Errorf("passive: writing output: %w", err)
	}

	return modules.Output{
		Files:   map[string]string{"subs_passive": outPath},
		Summary: fmt.Sprintf("%d unique subdomains found (passive sources)", len(subs)),
		Count:   len(subs),
	}, nil
}

// runToolLines executes an external binary and adds each non-empty line of
// its output (lowercased) to the set `into`.
func (m *Module) runToolLines(ctx context.Context, bin string, args []string, into map[string]struct{}) error {
	result, err := m.run.Run(ctx, bin, args, nil)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimSpace(strings.ToLower(line))
		if line != "" {
			into[line] = struct{}{}
		}
	}
	return nil
}

// queryCrtSh queries crt.sh over direct HTTP (no external binary) and
// extracts domain names from each certificate's name_value field. crt.sh
// often fails transiently (rate-limit, overload), so we retry twice with a
// small backoff before giving up on this source.
func queryCrtSh(ctx context.Context, domain string, into map[string]struct{}) error {
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		if err := queryCrtShOnce(ctx, domain, into); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return fmt.Errorf("after %d attempts: %w", maxAttempts, lastErr)
}

func queryCrtShOnce(ctx context.Context, domain string, into map[string]struct{}) error {
	endpoint := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// crt.sh is notoriously flaky: under load it answers with an HTML error
	// page (rate-limit, challenge) instead of the expected JSON. We detect
	// that explicitly rather than let json.Unmarshal fail cryptically.
	if resp.StatusCode != http.StatusOK {
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return fmt.Errorf("crt.sh returned HTTP %d (likely rate-limited or temporarily down): %s", resp.StatusCode, snippet)
	}

	var records []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &records); err != nil {
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return fmt.Errorf("crt.sh returned non-JSON response (likely rate-limited or temporarily down): %s", snippet)
	}

	for _, rec := range records {
		for _, name := range strings.Split(rec.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if name != "" {
				into[name] = struct{}{}
			}
		}
	}
	return nil
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
	fmt.Fprintf(os.Stderr, "passive: "+format+"\n", args...)
}
