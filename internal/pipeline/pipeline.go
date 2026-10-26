// Package pipeline is the multi-module orchestrator: it builds the dependency
// graph from modules.Module.DependsOn() and runs every independent branch
// concurrently (the "pipeline" level of concurrency, on top of the
// intra-module level and the per-command -t threads level). Registry is the
// only place to touch to wire a new module into `recon-cli scan`.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/modules/activebrute"
	"github.com/Qtlas/BugBounty-recon/internal/modules/alive"
	"github.com/Qtlas/BugBounty-recon/internal/modules/dirbrute"
	"github.com/Qtlas/BugBounty-recon/internal/modules/githubintel"
	"github.com/Qtlas/BugBounty-recon/internal/modules/infra"
	"github.com/Qtlas/BugBounty-recon/internal/modules/jsanalysis"
	"github.com/Qtlas/BugBounty-recon/internal/modules/merge"
	"github.com/Qtlas/BugBounty-recon/internal/modules/originip"
	"github.com/Qtlas/BugBounty-recon/internal/modules/osintdork"
	"github.com/Qtlas/BugBounty-recon/internal/modules/passive"
	"github.com/Qtlas/BugBounty-recon/internal/modules/portscan"
	"github.com/Qtlas/BugBounty-recon/internal/modules/takeover"
	"github.com/Qtlas/BugBounty-recon/internal/modules/urldiscovery"
	"github.com/Qtlas/BugBounty-recon/internal/modules/vhost"
	"github.com/Qtlas/BugBounty-recon/internal/runner"
	"github.com/Qtlas/BugBounty-recon/internal/state"
)

// Factory builds a module from the config and a runner of its own (each
// module may have a different per-command timeout, see config.TimeoutFor).
type Factory func(cfg *config.Config, r *runner.Runner) modules.Module

// Registry lists every module wired into the pipeline. Adding a module =
// registering it here; its dependency graph comes from DependsOn(), and
// `recon-cli run`/`scan` need nothing else. Registration order does not
// matter (execution order comes from the graph); listed in graph order for
// readability.
var Registry = map[string]Factory{
	passive.Name:      func(cfg *config.Config, r *runner.Runner) modules.Module { return passive.New(cfg, r) },
	activebrute.Name:  func(cfg *config.Config, r *runner.Runner) modules.Module { return activebrute.New(cfg, r) },
	infra.Name:        func(cfg *config.Config, r *runner.Runner) modules.Module { return infra.New(cfg, r) },
	merge.Name:        func(cfg *config.Config, r *runner.Runner) modules.Module { return merge.New(cfg, r) },
	alive.Name:        func(cfg *config.Config, r *runner.Runner) modules.Module { return alive.New(cfg, r) },
	originip.Name:     func(cfg *config.Config, r *runner.Runner) modules.Module { return originip.New(cfg, r) },
	vhost.Name:        func(cfg *config.Config, r *runner.Runner) modules.Module { return vhost.New(cfg, r) },
	urldiscovery.Name: func(cfg *config.Config, r *runner.Runner) modules.Module { return urldiscovery.New(cfg, r) },
	jsanalysis.Name:   func(cfg *config.Config, r *runner.Runner) modules.Module { return jsanalysis.New(cfg, r) },
	dirbrute.Name:     func(cfg *config.Config, r *runner.Runner) modules.Module { return dirbrute.New(cfg, r) },
	githubintel.Name:  func(cfg *config.Config, r *runner.Runner) modules.Module { return githubintel.New(cfg, r) },
	portscan.Name:     func(cfg *config.Config, r *runner.Runner) modules.Module { return portscan.New(cfg, r) },
	takeover.Name:     func(cfg *config.Config, r *runner.Runner) modules.Module { return takeover.New(cfg, r) },
	osintdork.Name:    func(cfg *config.Config, r *runner.Runner) modules.Module { return osintdork.New(cfg, r) },
}

// Names returns every registered module, sorted, used as the default
// selection of `recon-cli scan`.
func Names() []string {
	names := make([]string, 0, len(Registry))
	for name := range Registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// RunOne executes a single module outside the DAG (its dependencies are
// assumed already on disk) and records its result in st via Record — success
// or failure. Does not call st.Save: the caller persists when ready. Shared
// as-is by `recon-cli run <module>` and the matching MCP handler, so CLI and
// MCP run exactly the same path.
func RunOne(ctx context.Context, cfg *config.Config, name string, in modules.Input, st *state.State) (modules.Output, error) {
	factory, ok := Registry[name]
	if !ok {
		return modules.Output{}, fmt.Errorf("unknown module %q", name)
	}
	mod := factory(cfg, runner.New(cfg.TimeoutFor(name)))
	started := time.Now()
	out, runErr := mod.Run(ctx, in)
	finished := time.Now()
	st.Record(name, started, finished, out, runErr)
	return out, runErr
}

// Run executes the `selected` modules honoring their dependencies: each
// module waits for its *selected* dependencies to finish successfully before
// starting, but independent branches of the DAG run concurrently. A
// dependency absent from `selected` is considered already satisfied (for
// example, re-running one module with its input already present on disk).
//
// If ctx is canceled (Ctrl+C or quit): modules already started let their
// external commands be killed by exec.CommandContext (see internal/runner),
// and modules not yet started are marked "interrupted" in st without being
// run. Each state transition is saved immediately so that a `recon-cli
// status` from another terminal sees progress live.
func Run(ctx context.Context, cfg *config.Config, in modules.Input, selected []string, st *state.State) {
	mods := make(map[string]modules.Module, len(selected))
	for _, name := range selected {
		factory, ok := Registry[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "pipeline: unknown module %q, skipping\n", name)
			continue
		}
		mods[name] = factory(cfg, runner.New(cfg.TimeoutFor(name)))
	}

	done := make(map[string]chan struct{}, len(mods))
	for name := range mods {
		done[name] = make(chan struct{})
	}

	var mu sync.Mutex
	ok := make(map[string]bool, len(mods))

	var g errgroup.Group
	for name, mod := range mods {
		name, mod := name, mod
		g.Go(func() error {
			defer close(done[name])

			for _, dep := range mod.DependsOn() {
				ch, inSet := done[dep]
				if !inSet {
					// Dependency not re-run in this run: assume its output is
					// already on disk (standalone usage).
					continue
				}
				select {
				case <-ch:
				case <-ctx.Done():
					interrupt(st, name, "not started: "+ctx.Err().Error())
					return nil
				}
				mu.Lock()
				depOK := ok[dep]
				mu.Unlock()
				if !depOK {
					interrupt(st, name, fmt.Sprintf("skipped: dependency %q did not complete successfully", dep))
					mu.Lock()
					ok[name] = false
					mu.Unlock()
					return nil
				}
			}
			if ctx.Err() != nil {
				interrupt(st, name, "not started: "+ctx.Err().Error())
				return nil
			}

			started := time.Now()
			st.SetRunning(name, started)
			st.Save()

			out, runErr := mod.Run(ctx, in)
			finished := time.Now()
			st.Record(name, started, finished, out, runErr)
			st.Save()

			// A "skipped" module (ErrNoInput: nothing to process) counts as a
			// successful no-op for dependencies: its dependents run and skip in
			// turn on their own empty input, rather than being marked as a
			// failed dependency.
			skipped := errors.Is(runErr, modules.ErrNoInput)
			mu.Lock()
			ok[name] = runErr == nil || skipped
			mu.Unlock()
			if runErr != nil && !skipped {
				fmt.Fprintf(os.Stderr, "pipeline: %s failed: %v\n", name, runErr)
			} else if skipped {
				fmt.Fprintf(os.Stderr, "pipeline: %s skipped: %v\n", name, runErr)
			}
			return nil
		})
	}
	g.Wait()
}

func interrupt(st *state.State, module, reason string) {
	st.SetInterrupted(module, reason)
	st.Save()
}
