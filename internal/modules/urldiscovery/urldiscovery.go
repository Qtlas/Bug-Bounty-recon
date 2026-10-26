// Package urldiscovery implements URL and endpoint discovery. Four
// independent sources (waybackurls, waymore, gau, katana) run in parallel
// over alive_subs.txt, merged into all_urls.txt, then categorized by regex
// (JS, API, admin, sensitive...) to feed the downstream modules without them
// redoing this sorting.
package urldiscovery

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

const Name = "urldiscovery"

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
	aliveSubsPath := filepath.Join(in.OutputDir, "alive_subs.txt")
	hosts := readLines(aliveSubsPath)
	if len(hosts) == 0 {
		return modules.Output{}, modules.NoInput(fmt.Sprintf("urldiscovery: %s is empty or missing (run alive first)", aliveSubsPath))
	}
	stdin := strings.Join(hosts, "\n")

	type source struct {
		name string
		fn   func() []string
	}
	sources := []source{
		{"waybackurls", func() []string { return m.runToolLines(ctx, "waybackurls", nil, stdin) }},
		{"waymore", func() []string { return m.runWaymore(ctx, aliveSubsPath, in.OutputDir) }},
		{"gau", func() []string {
			return m.runToolLines(ctx, "gau", []string{"--threads", fmt.Sprintf("%d", m.cfg.ThreadsFor(Name))}, stdin)
		}},
		{"katana", func() []string {
			return m.runToolLines(ctx, "katana", []string{
				"-u", aliveSubsPath, "-jc", "-kf", "all", "-d", "5", "-headless", "-fx", "-aff", "-fs", "rdn", "-f", "url", "-silent",
			}, "")
		}},
	}

	results := make([][]string, len(sources))
	var g errgroup.Group
	for i, src := range sources {
		i, src := i, src
		g.Go(func() error {
			results[i] = src.fn()
			return nil
		})
	}
	g.Wait()

	// Individual outputs kept, useful to compare source by source if one is
	// noisy.
	names := []string{"urls_wayback.txt", "urls_waymore.txt", "urls_gau.txt", "urls_katana.txt"}
	found := make(map[string]struct{})
	for i, lines := range results {
		if err := writeLines(filepath.Join(in.OutputDir, names[i]), lines); err != nil {
			warn("writing %s (continuing): %v", names[i], err)
		}
		for _, l := range lines {
			found[l] = struct{}{}
		}
	}

	allURLs := make([]string, 0, len(found))
	for u := range found {
		if u != "" {
			allURLs = append(allURLs, u)
		}
	}
	sort.Strings(allURLs)

	allURLsPath := filepath.Join(in.OutputDir, "all_urls.txt")
	if err := writeLines(allURLsPath, allURLs); err != nil {
		return modules.Output{}, fmt.Errorf("urldiscovery: writing all_urls.txt: %w", err)
	}

	files := map[string]string{"all_urls": allURLsPath}
	catCounts := categorize(allURLs)
	for cat, urls := range catCounts {
		path := filepath.Join(in.OutputDir, cat+".txt")
		if err := writeLines(path, urls); err != nil {
			warn("writing %s.txt (continuing): %v", cat, err)
			continue
		}
		files[cat] = path
	}

	return modules.Output{
		Files:   files,
		Summary: fmt.Sprintf("%d unique URLs (wayback=%d waymore=%d gau=%d katana=%d)", len(allURLs), len(results[0]), len(results[1]), len(results[2]), len(results[3])),
		Count:   len(allURLs),
	}, nil
}

func (m *Module) runToolLines(ctx context.Context, bin string, args []string, stdin string) []string {
	var result *runner.Result
	var err error
	if stdin != "" {
		result, err = m.run.RunWithInput(ctx, bin, args, stdin, nil)
	} else {
		result, err = m.run.Run(ctx, bin, args, nil)
	}
	if err != nil {
		warn("%s failed (continuing): %v", bin, err)
		return nil
	}
	return splitNonEmpty(result.Stdout)
}

// runWaymore writes its result via -oU, not to stdout.
func (m *Module) runWaymore(ctx context.Context, aliveSubsPath, outputDir string) []string {
	outPath := filepath.Join(outputDir, "urls_waymore.txt")
	args := []string{"-i", aliveSubsPath, "-mode", "U", "-l", "1000", "-from", "2021", "-oU", outPath}
	if _, err := m.run.Run(ctx, "waymore", args, nil); err != nil {
		warn("waymore failed (continuing): %v", err)
		return nil
	}
	return readLines(outPath)
}

// categoryRules: a URL may match several categories (an /api/upload endpoint
// is both "api" and "upload"), deliberately non-exclusive. Simple regex
// heuristics, to refine if too noisy on a real target.
var categoryRules = map[string]*regexp.Regexp{
	"js_urls":          regexp.MustCompile(`(?i)\.js(\?|$)`),
	"api_urls":         regexp.MustCompile(`(?i)/(api|graphql|v[0-9]+)(/|$|\?)`),
	"admin_urls":       regexp.MustCompile(`(?i)/(admin|wp-admin|manage|dashboard|console)(/|$|\?)`),
	"auth_urls":        regexp.MustCompile(`(?i)/(login|logout|auth|oauth|signin|signup|sso|register)(/|$|\?)`),
	"upload_urls":      regexp.MustCompile(`(?i)/(upload|import|attachment)(/|$|\?)`),
	"sensitive_urls":   regexp.MustCompile(`(?i)\.(env|sql|bak|zip|tar|gz|pem|key|log|conf|config|ya?ml|git|DS_Store)(\?|$)`),
	"idor_candidates":  regexp.MustCompile(`(?i)/(user|account|order|invoice|profile|document|file)s?/[0-9]+(/|$|\?)`),
	"redirect_urls":    regexp.MustCompile(`(?i)[?&](redirect|url|next|return|callback|continue)=`),
	"cloud_creds_urls": regexp.MustCompile(`(?i)(akia[0-9a-z]{16}|s3\.amazonaws\.com|\.s3\.[a-z0-9-]+\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com)`),
}

func categorize(urls []string) map[string][]string {
	out := make(map[string][]string, len(categoryRules))
	for _, u := range urls {
		for cat, re := range categoryRules {
			if re.MatchString(u) {
				out[cat] = append(out[cat], u)
			}
		}
	}
	return out
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
	fmt.Fprintf(os.Stderr, "urldiscovery: "+format+"\n", args...)
}
