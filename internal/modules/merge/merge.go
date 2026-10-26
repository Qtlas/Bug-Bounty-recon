// Package merge implements merge_and_resolve. It is the convergence point
// between the subdomain-enumeration branch (passive + activebrute) and the
// infrastructure branch (infra): it merges every subs_*.txt + ptr_domains.txt
// into one deduplicated all_subs.txt, consumed by alive (the central hub) and
// by takeover.
package merge

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/runner"
)

const Name = "merge_resolve"

// sourceFiles lists, in display-preference order, the files the preceding
// modules may have produced. A missing file (module not run, or run with no
// result) is ignored without error: merge must work even with a subset of the
// upstream modules already executed.
var sourceFiles = []string{
	"subs_passive.txt",        // passive
	"subs_bruteforce.txt",     // activebrute
	"subs_permuted_alive.txt", // activebrute
	"ptr_domains.txt",         // infra
}

type Module struct {
	cfg *config.Config
	run *runner.Runner
}

func New(cfg *config.Config, r *runner.Runner) *Module {
	return &Module{cfg: cfg, run: r}
}

func (m *Module) Name() string { return Name }

// DependsOn: waits for activebrute (which already depends on passive) and
// infra, the two branches that converge here before alive.
func (m *Module) DependsOn() []string { return []string{"activebrute", "infra"} }

func (m *Module) Run(ctx context.Context, in modules.Input) (modules.Output, error) {
	found := make(map[string]struct{})
	var present []string
	for _, name := range sourceFiles {
		path := filepath.Join(in.OutputDir, name)
		lines, err := readLines(path)
		if err != nil {
			continue // file absent: source module not run, not an error
		}
		present = append(present, name)
		for _, l := range lines {
			found[strings.ToLower(strings.TrimSpace(l))] = struct{}{}
		}
	}

	subs := make([]string, 0, len(found))
	for s := range found {
		if s != "" {
			subs = append(subs, s)
		}
	}
	sort.Strings(subs)

	outPath := filepath.Join(in.OutputDir, "all_subs.txt")
	if err := writeLines(outPath, subs); err != nil {
		return modules.Output{}, fmt.Errorf("merge_resolve: writing all_subs.txt: %w", err)
	}

	return modules.Output{
		Files:   map[string]string{"all_subs": outPath},
		Summary: fmt.Sprintf("%d unique hosts merged from %s", len(subs), strings.Join(present, ", ")),
		Count:   len(subs),
	}, nil
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(data), "\n"), nil
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
