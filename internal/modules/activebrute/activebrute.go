// Package activebrute implements active subdomain bruteforce: active DNS
// bruteforce (puredns) plus permutations over the passive results (gotator),
// with a fallback to HTTP fuzzing (ffuf) if the target answers with wildcard
// DNS (which would make puredns bruteforce useless).
package activebrute

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/ratelimit"
	"github.com/Qtlas/BugBounty-recon/internal/runner"
)

const Name = "activebrute"

const randomLabelLen = 20

type Module struct {
	cfg *config.Config
	run *runner.Runner
}

func New(cfg *config.Config, r *runner.Runner) *Module {
	return &Module{cfg: cfg, run: r}
}

func (m *Module) Name() string { return Name }

// DependsOn: gotator needs subs_passive.txt (output of passive) as its
// permutation base, see Input.SubsFile.
func (m *Module) DependsOn() []string { return []string{"passive"} }

func (m *Module) Run(ctx context.Context, in modules.Input) (modules.Output, error) {
	if in.Domain == "" {
		return modules.Output{}, fmt.Errorf("activebrute: domain is required")
	}
	if m.cfg.Wordlists.DNS == "" {
		return modules.Output{}, fmt.Errorf("activebrute: wordlists.dns is required")
	}
	if m.cfg.Resolvers == "" {
		return modules.Output{}, fmt.Errorf("activebrute: resolvers is required")
	}
	if in.SubsFile == "" {
		return modules.Output{}, fmt.Errorf("activebrute: subs file (passive output) is required")
	}

	if err := os.MkdirAll(in.OutputDir, 0o755); err != nil {
		return modules.Output{}, fmt.Errorf("activebrute: creating output dir: %w", err)
	}

	bruteforcePath := filepath.Join(in.OutputDir, "subs_bruteforce.txt")
	permutedAlivePath := filepath.Join(in.OutputDir, "subs_permuted_alive.txt")

	// The two branches are independent: gotator consumes only subs_passive.txt
	// (output of passive), not the bruteforce output below. Run in parallel,
	// the module takes the slowest branch's time rather than their sum.
	var wildcard bool
	var permutedCount int
	var g errgroup.Group
	g.Go(func() error {
		var err error
		wildcard, err = detectWildcard(ctx, in.Domain)
		if err != nil {
			warn("wildcard detection failed, assuming no wildcard (continuing): %v", err)
		}
		if wildcard {
			warn("wildcard DNS detected on %s, switching to ffuf HTTP fuzzing instead of puredns bruteforce", in.Domain)
			if err := m.bruteforceViaFfuf(ctx, in.Domain, bruteforcePath); err != nil {
				warn("ffuf fallback bruteforce failed (continuing): %v", err)
			}
		} else {
			if err := m.bruteforceViaPuredns(ctx, in.Domain, bruteforcePath); err != nil {
				warn("puredns bruteforce failed (continuing): %v", err)
			}
		}
		return nil
	})
	g.Go(func() error {
		var err error
		permutedCount, err = m.permuteAndResolve(ctx, in.SubsFile, in.OutputDir, permutedAlivePath)
		if err != nil {
			warn("permutation step failed (continuing): %v", err)
		}
		return nil
	})
	g.Wait()

	bruteforceCount := len(readLines(bruteforcePath))

	files := map[string]string{
		"subs_bruteforce":     bruteforcePath,
		"subs_permuted_alive": permutedAlivePath,
	}
	summary := fmt.Sprintf("%d subdomains from bruteforce (wildcard=%v), %d alive after permutation", bruteforceCount, wildcard, permutedCount)

	return modules.Output{
		Files:   files,
		Summary: summary,
		Count:   bruteforceCount + permutedCount,
	}, nil
}

// bruteforceViaPuredns runs the standard DNS bruteforce.
func (m *Module) bruteforceViaPuredns(ctx context.Context, domain, outPath string) error {
	args := []string{"bruteforce", m.cfg.Wordlists.DNS, domain, "-r", m.cfg.Resolvers, "-w", outPath}
	_, err := m.run.Run(ctx, "puredns", args, nil)
	return err
}

// bruteforceViaFfuf is the fallback for a wildcard-DNS target: direct HTTP
// fuzzing, insensitive to an always-positive DNS resolution. We stream the
// output line by line to feed the blocking detector (consecutive 403/429)
// during the run.
func (m *Module) bruteforceViaFfuf(ctx context.Context, domain, outPath string) error {
	threads := m.cfg.ThreadsFor(Name)
	url := fmt.Sprintf("https://FUZZ.%s", domain)
	args := []string{
		"-u", url,
		"-w", m.cfg.Wordlists.DNS,
		"-mc", "200,301,302,403",
		"-t", fmt.Sprintf("%d", threads),
		"-s", // silent: only result lines
	}

	detector := ratelimit.NewDetector(
		m.cfg.BlockingDetection.MaxConsecutive403,
		m.cfg.BlockingDetection.MaxConsecutive429,
		m.cfg.BlockingDetection.OnTrigger,
	)
	lineRe := regexp.MustCompile(`^(\S+)\s+\[Status:\s*(\d+)`)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var aborted bool
	found := make(map[string]struct{})
	_, err := m.run.Run(runCtx, "ffuf", args, func(line string) {
		match := lineRe.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			return
		}
		sub := match[1]
		var status int
		fmt.Sscanf(match[2], "%d", &status)
		found[strings.ToLower(sub)+"."+domain] = struct{}{}

		switch detector.Observe(status) {
		case ratelimit.ActionAbort:
			warn("blocking detected (status %d), aborting ffuf fallback per blocking_detection.on_trigger=abort", status)
			aborted = true
			cancel()
		case ratelimit.ActionPauseAndReduce:
			warn("blocking detected on ffuf fallback, pausing %ds (rate not reducible mid-run)", m.cfg.BlockingDetection.PauseSeconds)
			time.Sleep(time.Duration(m.cfg.BlockingDetection.PauseSeconds) * time.Second)
		case ratelimit.ActionAlertOnly:
			warn("blocking detected on ffuf fallback (alert only, continuing)")
		}
	})
	// An intentional abort via cancel() surfaces as a context error: not a
	// real failure, keep the results already collected.
	if err != nil && !aborted {
		return err
	}

	subs := make([]string, 0, len(found))
	for s := range found {
		subs = append(subs, s)
	}
	sort.Strings(subs)
	return writeLines(outPath, subs)
}

// permuteAndResolve runs gotator over the passive subdomains to generate
// plausible variants (dev-, staging-, api-v2...), then resolves them with
// puredns. Returns the number of alive permuted subdomains.
//
// If wordlists.permutations is not set, we use -prefixes: gotator's built-in
// prefix list (admin, dev, staging, api...), so we never depend on an
// external file provided by hand.
func (m *Module) permuteAndResolve(ctx context.Context, subsFile, outputDir, permutedAlivePath string) (int, error) {
	args := []string{
		"-sub", subsFile,
		"-depth", "1",
		"-numbers", "3",
		"-md",
	}
	if m.cfg.Wordlists.Permutations != "" {
		args = append(args, "-perm", m.cfg.Wordlists.Permutations)
	} else {
		args = append(args, "-prefixes")
	}
	result, err := m.run.Run(ctx, "gotator", args, nil)
	if err != nil {
		return 0, fmt.Errorf("gotator: %w", err)
	}

	permuted := make(map[string]struct{})
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimSpace(strings.ToLower(line))
		if line != "" {
			permuted[line] = struct{}{}
		}
	}
	permutedList := make([]string, 0, len(permuted))
	for s := range permuted {
		permutedList = append(permutedList, s)
	}
	sort.Strings(permutedList)

	permutedPath := filepath.Join(outputDir, "subs_permuted.txt")
	if err := writeLines(permutedPath, permutedList); err != nil {
		return 0, fmt.Errorf("writing subs_permuted.txt: %w", err)
	}
	if len(permutedList) == 0 {
		return 0, nil
	}

	resolveArgs := []string{"resolve", permutedPath, "-r", m.cfg.Resolvers, "-w", permutedAlivePath}
	if _, err := m.run.Run(ctx, "puredns", resolveArgs, nil); err != nil {
		return 0, fmt.Errorf("puredns resolve: %w", err)
	}

	return len(readLines(permutedAlivePath)), nil
}

// detectWildcard queries two improbable random labels under domain: if both
// resolve, the target answers positively to any subdomain (wildcard DNS),
// which invalidates puredns bruteforce.
func detectWildcard(ctx context.Context, domain string) (bool, error) {
	for i := 0; i < 2; i++ {
		label, err := randomLabel(randomLabelLen)
		if err != nil {
			return false, err
		}
		host := label + "." + domain
		lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		addrs, err := net.DefaultResolver.LookupHost(lookupCtx, host)
		cancel()
		if err != nil || len(addrs) == 0 {
			return false, nil
		}
	}
	return true, nil
}

func randomLabel(n int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b[i] = alphabet[idx.Int64()]
	}
	return string(b), nil
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
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
	fmt.Fprintf(os.Stderr, "activebrute: "+format+"\n", args...)
}
