// Package takeover implements the subdomain-takeover check. Two independent
// branches run in parallel: subzy (direct takeover detection) and dnsx -cname
// (raw CNAMEs, for manual investigation of cases subzy does not yet know).
package takeover

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/runner"
)

const Name = "takeover"

type Module struct {
	cfg *config.Config
	run *runner.Runner
}

func New(cfg *config.Config, r *runner.Runner) *Module {
	return &Module{cfg: cfg, run: r}
}

func (m *Module) Name() string { return Name }

// DependsOn: consumes all_subs.txt, the output of merge_and_resolve.
func (m *Module) DependsOn() []string { return []string{"merge_resolve"} }

func (m *Module) Run(ctx context.Context, in modules.Input) (modules.Output, error) {
	allSubsPath := filepath.Join(in.OutputDir, "all_subs.txt")
	if len(readLines(allSubsPath)) == 0 {
		return modules.Output{}, modules.NoInput(fmt.Sprintf("takeover: %s is empty or missing (run merge_resolve first)", allSubsPath))
	}

	takeoverPath := filepath.Join(in.OutputDir, "takeover_candidates.txt")
	dnsRecordsPath := filepath.Join(in.OutputDir, "dns_records.txt")

	var candidateCount, recordCount int
	var g errgroup.Group
	g.Go(func() error {
		candidateCount = m.runSubzy(ctx, allSubsPath, takeoverPath)
		return nil
	})
	g.Go(func() error {
		recordCount = m.runDnsxCname(ctx, allSubsPath, dnsRecordsPath)
		return nil
	})
	g.Wait()

	return modules.Output{
		Files: map[string]string{
			"takeover_candidates": takeoverPath,
			"dns_records":         dnsRecordsPath,
		},
		Summary: fmt.Sprintf("%d takeover candidates, %d CNAME records checked", candidateCount, recordCount),
		Count:   candidateCount,
	}, nil
}

func (m *Module) runSubzy(ctx context.Context, allSubsPath, outPath string) int {
	args := []string{"run", "--targets", allSubsPath, "--hide_fails", "--vuln"}
	result, err := m.run.Run(ctx, "subzy", args, nil)
	if err != nil {
		warn("subzy failed (continuing): %v", err)
		return 0
	}
	lines := splitNonEmpty(result.Stdout)
	if err := writeLines(outPath, lines); err != nil {
		warn("writing takeover_candidates.txt (continuing): %v", err)
	}
	return len(lines)
}

func (m *Module) runDnsxCname(ctx context.Context, allSubsPath, outPath string) int {
	args := []string{"-retry", "3", "-cname", "-l", allSubsPath, "-resp", "-silent"}
	result, err := m.run.Run(ctx, "dnsx", args, nil)
	if err != nil {
		warn("dnsx -cname failed (continuing): %v", err)
		return 0
	}
	lines := splitNonEmpty(result.Stdout)
	if err := writeLines(outPath, lines); err != nil {
		warn("writing dns_records.txt (continuing): %v", err)
	}
	return len(lines)
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
	fmt.Fprintf(os.Stderr, "takeover: "+format+"\n", args...)
}
