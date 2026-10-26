// Package runner is the single point of contact with external binaries
// (subfinder, httpx, ffuf, ...). Centralizing here keeps each module from
// reimplementing timeout handling, output capture, and presence checks.
package runner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Runner struct {
	Timeout time.Duration
}

func New(timeout time.Duration) *Runner {
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	return &Runner{Timeout: timeout}
}

// LineFunc is called for each line of stdout as it arrives, useful for a
// module that wants to inspect output live (for example, the blocking
// detector watching status codes returned by ffuf/httpx).
type LineFunc func(line string)

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// PythonScript builds the "python3 {path} {args...}" invocation for tools
// distributed as a plain script (no pip/go install package with a stable
// binary on PATH), see config.Config.ToolPath. ok=false if path is empty:
// the caller should warn-and-skip rather than guess a path.
func PythonScript(path string, args []string) (bin string, fullArgs []string, ok bool) {
	if path == "" {
		return "", nil, false
	}
	return "python3", append([]string{path}, args...), true
}

// EnsureInstalled checks that a binary is present on PATH before a module
// uses it, to fail explicitly rather than with a cryptic exec error in the
// middle of the pipeline. Also used by the doctor command.
func EnsureInstalled(bin string) error {
	if _, err := exec.LookPath(bin); err != nil {
		return fmt.Errorf("required tool %q not found on PATH: %w", bin, err)
	}
	return nil
}

// FirstInstalled returns the first of the given names present on PATH, and
// false if none. Useful for tools whose binary name varies by fork or by the
// casing `go install` produces (for example, AnalyticsRelationships vs
// analyticsrelationships). The caller passes the known variants; we take the
// first found rather than bet on one spelling.
func FirstInstalled(names ...string) (string, bool) {
	for _, n := range names {
		if _, err := exec.LookPath(n); err == nil {
			return n, true
		}
	}
	return "", false
}

// Run executes bin with args, streaming each line of stdout to onLine if
// provided (may be nil).
func (r *Runner) Run(ctx context.Context, bin string, args []string, onLine LineFunc) (*Result, error) {
	return r.run(ctx, bin, args, "", nil, onLine)
}

// RunWithInput executes bin with args like Run, but feeds it `stdin` on its
// standard input. Needed for binaries that take input piped on stdin rather
// than as an argument or file.
func (r *Runner) RunWithInput(ctx context.Context, bin string, args []string, stdin string, onLine LineFunc) (*Result, error) {
	return r.run(ctx, bin, args, stdin, nil, onLine)
}

// RunWithEnv executes bin with args like Run, adding `env` ("KEY=VALUE"
// entries) to the inherited environment. Needed for binaries that
// authenticate or configure themselves through an environment variable
// rather than a flag.
func (r *Runner) RunWithEnv(ctx context.Context, bin string, args []string, env []string, onLine LineFunc) (*Result, error) {
	return r.run(ctx, bin, args, "", env, onLine)
}

// RunWithInputEnv combines RunWithInput and RunWithEnv (for a binary that
// needs both stdin and an environment variable).
func (r *Runner) RunWithInputEnv(ctx context.Context, bin string, args []string, stdin string, env []string, onLine LineFunc) (*Result, error) {
	return r.run(ctx, bin, args, stdin, env, onLine)
}

func (r *Runner) run(ctx context.Context, bin string, args []string, stdin string, extraEnv []string, onLine LineFunc) (*Result, error) {
	if err := EnsureInstalled(bin); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe for %s: %w", bin, err)
	}
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", bin, err)
	}

	scanner := bufio.NewScanner(stdoutPipe)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		stdoutBuf.WriteString(line)
		stdoutBuf.WriteByte('\n')
		if onLine != nil {
			onLine(line)
		}
	}

	waitErr := cmd.Wait()
	result := &Result{
		Stdout: stdoutBuf.String(),
		Stderr: stderrBuf.String(),
	}
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		result.ExitCode = exitErr.ExitCode()
	}
	switch ctx.Err() {
	case context.DeadlineExceeded:
		return result, fmt.Errorf("%s timed out after %s", bin, r.Timeout)
	case context.Canceled:
		// Intentional stop (Ctrl+C / quit), not a real failure: keep whatever
		// stdout/stderr was already captured.
		return result, fmt.Errorf("%s interrupted: %w", bin, context.Canceled)
	}
	if waitErr != nil {
		return result, fmt.Errorf("running %s: %w (stderr: %s)", bin, waitErr, stderrBuf.String())
	}
	return result, nil
}
