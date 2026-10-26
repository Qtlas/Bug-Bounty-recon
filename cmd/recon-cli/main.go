// recon-cli runs a recon module in isolation, or the full pipeline
// concurrently (`scan`), without going through the MCP server — handy for
// debugging. cmd/recon-cli and cmd/recon-mcp share 100% of the logic in
// internal/.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/pipeline"
	"github.com/Qtlas/BugBounty-recon/internal/runner"
	"github.com/Qtlas/BugBounty-recon/internal/state"
	"github.com/Qtlas/BugBounty-recon/internal/target"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		cmdRun(os.Args[2:])
	case "scan":
		cmdScan(os.Args[2:])
	case "quit":
		cmdQuit(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "report":
		cmdReport(os.Args[2:])
	case "doctor":
		cmdDoctor()
	case "version":
		cmdVersion()
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Printf(`recon-cli usage:
  recon-cli run <module> --config recon.config.yaml [--domain example.com] [--subs-file subs_passive.txt]
  recon-cli scan --config recon.config.yaml [--domain example.com] [--modules %s]
  recon-cli quit --config recon.config.yaml
  recon-cli status --config recon.config.yaml
  recon-cli report --config recon.config.yaml
  recon-cli doctor
  recon-cli version

Available modules: %s
`, strings.Join(pipeline.Names(), ","), strings.Join(pipeline.Names(), ", "))
}

func cmdRun(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}
	moduleName := args[0]

	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "recon.config.yaml", "path to config file")
	domainOverride := fs.String("domain", "", "override scope.domain from config")
	subsFile := fs.String("subs-file", "", "path to a subdomains file (defaults to <output_dir>/subs_passive.txt)")
	if err := fs.Parse(args[1:]); err != nil {
		os.Exit(1)
	}

	if _, ok := pipeline.Registry[moduleName]; !ok {
		fmt.Printf("unknown module %q\n", moduleName)
		usage()
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	if *domainOverride != "" {
		cfg.Scope.Domain = *domainOverride
	}

	outputDir := filepath.Clean(cfg.OutputDir)
	if *subsFile == "" {
		*subsFile = filepath.Join(outputDir, "subs_passive.txt")
	}

	in := modules.Input{
		Domain:    cfg.Scope.Domain,
		OrgName:   cfg.Scope.OrgName,
		SubsFile:  *subsFile,
		OutputDir: outputDir,
	}

	// Same execution path as the MCP handler (pipeline.RunOne records the
	// result in st, success or failure). State is persisted even on failure,
	// so `recon-cli status` shows a failed module rather than silently
	// nothing, before exiting on fatal().
	st, stErr := state.Load(outputDir)
	if stErr != nil {
		// Unreadable state.json: run the module anyway in a throwaway
		// (non-persisted) state rather than abandoning the run.
		warn("could not load state.json (continuing without recording state): %v", stErr)
		st, _ = state.Load(os.TempDir())
	}

	out, runErr := pipeline.RunOne(context.Background(), cfg, moduleName, in, st)
	if stErr == nil {
		if err := st.Save(); err != nil {
			warn("could not save state.json (continuing): %v", err)
		}
	}

	if errors.Is(runErr, modules.ErrNoInput) {
		// Nothing to process (empty input): a no-op, not an error. Recorded
		// "skipped" in state.json, exit 0.
		fmt.Printf("skipped: %s\n", runErr)
		return
	}
	if runErr != nil {
		fatal(runErr)
	}
	printOutput(out)
}

// cmdScan runs the full pipeline (or the subset in --modules) honoring
// dependencies, with independent branches running concurrently. Ctrl+C or
// `recon-cli quit` from another terminal stops it cleanly: the context is
// canceled, in-flight external commands are killed, and modules not yet
// started are marked "interrupted".
func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	configPath := fs.String("config", "recon.config.yaml", "path to config file")
	domainOverride := fs.String("domain", "", "override scope.domain from config")
	modulesFlag := fs.String("modules", "", "comma-separated list of modules to run (default: all registered modules)")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	if *domainOverride != "" {
		cfg.Scope.Domain = *domainOverride
	}
	outputDir := filepath.Clean(cfg.OutputDir)

	selected := pipeline.Names()
	if *modulesFlag != "" {
		selected = strings.Split(*modulesFlag, ",")
	}

	release, err := pipeline.AcquireLock(outputDir, selected)
	if err != nil {
		fatal(err)
	}
	defer release()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := state.Load(outputDir)
	if err != nil {
		fatal(err)
	}
	in := modules.Input{
		Domain:    cfg.Scope.Domain,
		OrgName:   cfg.Scope.OrgName,
		SubsFile:  filepath.Join(outputDir, "subs_passive.txt"),
		OutputDir: outputDir,
	}

	fmt.Printf("Starting scan for %s (%s)\nModules: %s\n", cfg.Scope.Domain, outputDir, strings.Join(selected, ", "))
	fmt.Println("Type `status` or `quit` + Enter at any time (Ctrl+C, or `recon-cli quit`/`status` from another shell, also work).")
	fmt.Println()

	done := make(chan struct{})
	go func() {
		pipeline.Run(ctx, cfg, in, selected, st)
		close(done)
	}()
	go readInteractiveCommands(cfg, outputDir, stop, done)

	<-done

	if ctx.Err() != nil {
		fmt.Println("\nScan interrupted. Re-run `recon-cli scan` to resume remaining modules, or `recon-cli status` to see what's left.")
		return
	}
	// Serialize the report from the final state. Best-effort: a write failure
	// must not mask an otherwise successful scan (warn-and-continue); the user
	// still has state.json.
	if art, err := target.Write(cfg, st); err != nil {
		warn("could not write recon report (scan results are still in state.json): %v", err)
	} else {
		fmt.Printf("Report written:\n  %s\n  %s\n  %s\n", art.Recon, art.FunctionalityMap, art.Findings)
	}
	fmt.Println("\nScan finished. See `recon-cli status`.")
}

// cmdReport (re)generates the report files from the current state.json,
// without re-running any module. Useful after an interrupted `scan`, or after
// several standalone `run <module>`, to aggregate what has already run.
func cmdReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	configPath := fs.String("config", "recon.config.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	outputDir := filepath.Clean(cfg.OutputDir)

	st, err := state.Load(outputDir)
	if err != nil {
		fatal(err)
	}
	art, err := target.Write(cfg, st)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("Report written:\n  %s\n  %s\n  %s\n", art.Recon, art.FunctionalityMap, art.Findings)
}

// readInteractiveCommands reads stdin line by line while a scan runs, so
// `status`/`quit` can be typed in the same terminal instead of opening a
// second shell. `stop` is the stop() of signal.NotifyContext: calling it
// cancels the same context as a Ctrl+C or a `recon-cli quit` from another
// terminal, i.e. the same clean-shutdown path. Returns when `done` closes
// (scan finished) or stdin reaches EOF (e.g. scan launched with no terminal
// attached).
func readInteractiveCommands(cfg *config.Config, outputDir string, stop context.CancelFunc, done <-chan struct{}) {
	// The prompt only makes sense on an interactive terminal: if stdin is a
	// pipe/file (nohup, detached tmux...), print nothing so logs stay clean.
	interactive := false
	if fi, err := os.Stdin.Stat(); err == nil {
		interactive = fi.Mode()&os.ModeCharDevice != 0
	}
	prompt := func() {
		if interactive {
			fmt.Print("COMMAND > ")
		}
	}

	scanner := bufio.NewScanner(os.Stdin)
	prompt()
	for scanner.Scan() {
		select {
		case <-done:
			return
		default:
		}
		switch strings.TrimSpace(scanner.Text()) {
		case "":
		case "status":
			fmt.Println()
			printStatus(cfg, outputDir)
			fmt.Println()
		case "quit", "q", "exit":
			fmt.Println("stopping scan...")
			stop()
			return
		default:
			fmt.Println("unknown command, type `status` or `quit`")
		}
		prompt()
	}
}

// cmdQuit cleanly stops the `recon-cli scan` currently running for this
// target, if any (see internal/pipeline.Quit).
func cmdQuit(args []string) {
	fs := flag.NewFlagSet("quit", flag.ExitOnError)
	configPath := fs.String("config", "recon.config.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	outputDir := filepath.Clean(cfg.OutputDir)

	if err := pipeline.Quit(outputDir); err != nil {
		fatal(err)
	}
	fmt.Println("stop signal sent, the scan will finish its current step and exit")
}

// cmdStatus shows, for the target of the given config, whether a scan is
// currently running (via the lock), which modules have already run (with
// their result) and which remain, by comparing state.json to the full
// roadmap (state.Roadmap).
func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	configPath := fs.String("config", "recon.config.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	printStatus(cfg, filepath.Clean(cfg.OutputDir))
}

// printStatus is the display logic shared between `recon-cli status` (from
// another terminal) and the interactive `status` command typed inside a
// running `recon-cli scan` (see cmdScan).
func printStatus(cfg *config.Config, outputDir string) {
	fmt.Printf("Target: %s\n", cfg.Scope.Domain)
	fmt.Printf("Output dir: %s\n", outputDir)

	if info, running := pipeline.Status(outputDir); running {
		fmt.Printf("Scan: RUNNING (pid %d, started %s, elapsed %s)\n\n", info.PID, info.StartedAt.Format("2006-01-02 15:04:05"), time.Since(info.StartedAt).Round(time.Second))
	} else {
		fmt.Println("Scan: idle")
		fmt.Println()
	}

	st, err := state.Load(outputDir)
	if err != nil {
		warn("could not load state.json: %v", err)
		return
	}

	fmt.Println("Done / in progress:")
	anyDone := false
	running := 0
	for _, r := range state.Roadmap {
		e, ok := st.Entries[r.Module]
		if !ok {
			continue
		}
		anyDone = true
		if e.Status == state.StatusRunning {
			running++
		}
		mark := statusMark(e.Status)
		ts := e.FinishedAt
		if e.Status == state.StatusRunning {
			ts = e.StartedAt
		}
		fmt.Printf("  [%-4s] %-5s %-14s %s  %s\n", mark, r.ID, r.Module, ts.Format("2006-01-02 15:04:05"), e.Summary)
		if e.Status == state.StatusFailed || e.Status == state.StatusInterrupted {
			fmt.Printf("           %s\n", e.Error)
		}
	}
	if !anyDone {
		fmt.Println("  (none yet)")
	}

	// "Not started yet" = modules with no entry in state.json (never run), to
	// distinguish from modules still in progress ([RUN] above): a running
	// module already has an entry, so it is not "remaining".
	fmt.Println("\nNot started yet:")
	anyRemaining := false
	for _, r := range state.Roadmap {
		if _, ok := st.Entries[r.Module]; ok {
			continue
		}
		anyRemaining = true
		note := ""
		if !r.Implemented {
			note = " (not implemented yet)"
		}
		fmt.Printf("  [ ]      %-5s %-14s %s%s\n", r.ID, r.Module, r.Phase, note)
	}
	if !anyRemaining {
		if running > 0 {
			fmt.Printf("  (all modules started; %d still in progress)\n", running)
		} else {
			fmt.Println("  (nothing left in the current roadmap)")
		}
	}
}

func statusMark(s state.Status) string {
	switch s {
	case state.StatusDone:
		return "OK"
	case state.StatusFailed:
		return "FAIL"
	case state.StatusRunning:
		return "RUN"
	case state.StatusInterrupted:
		return "STOP"
	case state.StatusSkipped:
		return "SKIP"
	default:
		return "?"
	}
}

// cmdDoctor lists the external binaries required by the wired modules and
// reports which are missing from PATH.
func cmdDoctor() {
	tools := []string{
		"subfinder", "assetfinder", "findomain", "amass", // passive
		"massdns", "puredns", "gotator", "ffuf", // activebrute
		"asnmap", "mapcidr", "dnsx", "metabigor", // infra
		"httpx", "whatweb", "webanalyze", "gowitness", // alive
		"originiphunter", "analyticsrelationships", // originip (favup: see tool_paths.favup)
		// vhost (hosthunter: see tool_paths.hosthunter, ffuf already listed)
		"waybackurls", "waymore", "gau", "katana", // urldiscovery
		"subjs", "jsleak", "trufflehog", // jsanalysis (lazyegg: see tool_paths.lazyegg)
		"dirsearch", "bfac", "feroxbuster", // dirbrute (feroxbuster optional, modules.fast_dirbrute)
		// githubintel: gitleaks + GitDorker/metafinder/git-wild-hunt (PATH commands), trufflehog already listed
		"gitleaks", "gitdorker", "metafinder", "git-wild-hunt",
		"naabu", "nmap", // portscan
		"subzy",   // takeover (dnsx already listed)
		"python3", // required by modules that invoke a script via tool_paths
	}
	// A few tools have a binary whose casing/name varies by fork or by what
	// `go install` produces: accept any known variant present on PATH.
	variants := map[string][]string{
		"analyticsrelationships": {"analyticsrelationships", "AnalyticsRelationships"},
		"gitdorker":              {"gitdorker", "GitDorker"},
		"git-wild-hunt":          {"git-wild-hunt", "gitwildhunt"},
	}
	for _, t := range tools {
		ok := runner.EnsureInstalled(t) == nil
		if alt, has := variants[t]; has {
			_, ok = runner.FirstInstalled(alt...)
		}
		if ok {
			fmt.Printf("[OK]      %s\n", t)
		} else {
			fmt.Printf("[MISSING] %s\n", t)
		}
	}
}

// cmdVersion prints the git revision and build state, read from the build
// info `go build` embeds by default from a git repository. Lets you check at
// a glance that you are not running a stale binary. "unknown" if built
// outside a repo or with -buildvcs=false.
func cmdVersion() {
	rev, when, dirty := "unknown", "", ""
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.time":
				when = s.Value
			case "vcs.modified":
				if s.Value == "true" {
					dirty = " (modified locally, uncommitted)"
				}
			}
		}
		fmt.Printf("recon-cli commit %s%s\n", rev, dirty)
		if when != "" {
			fmt.Printf("  committed at %s\n", when)
		}
		fmt.Printf("  built with %s\n", info.GoVersion)
		return
	}
	fmt.Printf("recon-cli commit %s\n", rev)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func warn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "recon-cli: "+format+"\n", args...)
}

func printOutput(out modules.Output) {
	fmt.Println(out.Summary)
	for name, path := range out.Files {
		fmt.Printf("  %s -> %s\n", name, path)
	}
}
