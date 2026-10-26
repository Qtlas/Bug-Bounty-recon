// Package modules defines the contract every recon module implements. The
// orchestrator (internal/pipeline) builds the dependency graph solely from
// DependsOn(), so adding a module never requires touching the scheduler.
package modules

import (
	"context"
	"errors"
	"fmt"
)

// ErrNoInput signals that a module has nothing to process because its input
// file is absent or empty — typically an upstream module succeeded but
// produced no results. This is not a failure: the state record marks it
// "skipped" rather than "failed", and the pipeline treats it as a successful
// no-op with respect to dependencies (its dependents still run and decide for
// themselves whether to skip on empty input, instead of being reported as a
// failed dependency). Distinct from a real failure (a tool crash, malformed
// output).
var ErrNoInput = errors.New("no input to process")

// NoInput wraps ErrNoInput with a readable reason while remaining detectable
// via errors.Is(err, ErrNoInput).
func NoInput(reason string) error {
	return fmt.Errorf("%w: %s", ErrNoInput, reason)
}

// Input holds the data a module may consume. A module reads only the fields
// it needs (for example, the passive module uses only Domain).
type Input struct {
	Domain    string
	OrgName   string
	SubsFile  string // path to a subdomains file, for modules that consume one
	OutputDir string
}

// Output is what a module produces: the files written to disk, plus a short
// summary for surfaces that must not receive the full raw content (for
// example, an MCP tool over a module that can emit thousands of lines).
type Output struct {
	Files   map[string]string // logical name -> path of the written file
	Summary string
	Count   int
}

type Module interface {
	Name() string
	DependsOn() []string
	Run(ctx context.Context, in Input) (Output, error)
}
