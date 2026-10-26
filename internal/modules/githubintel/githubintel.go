// Package githubintel implements GitHub/source-code intelligence. Nearly
// independent of the rest of the pipeline (needs only domain/org_name/
// github_token): DependsOn() -> nil, so it can run in parallel with the whole
// chain. GitDorker, metafinder and git-wild-hunt are invoked directly by
// their name on PATH (installed as commands, not referenced via tool_paths);
// GitDorker and git-wild-hunt have variable-case names, resolved via
// runner.FirstInstalled.
package githubintel

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/runner"
)

const Name = "githubintel"

type Module struct {
	cfg *config.Config
	run *runner.Runner
}

func New(cfg *config.Config, r *runner.Runner) *Module {
	return &Module{cfg: cfg, run: r}
}

func (m *Module) Name() string { return Name }

// DependsOn returns nil: independent, consumes only domain/org_name/
// github_token.
func (m *Module) DependsOn() []string { return nil }

func (m *Module) Run(ctx context.Context, in modules.Input) (modules.Output, error) {
	if in.Domain == "" && in.OrgName == "" {
		return modules.Output{}, fmt.Errorf("githubintel: domain or org_name is required")
	}

	gitdorkerPath := filepath.Join(in.OutputDir, "gitdorker_results.txt")
	trufflehogPath := filepath.Join(in.OutputDir, "trufflehog_target.json")
	metadataPath := filepath.Join(in.OutputDir, "metadata.txt")
	gitWildHuntPath := filepath.Join(in.OutputDir, "git_wild_hunt_results.txt")
	gitlabPath := filepath.Join(in.OutputDir, "gitlab_discovery.txt")

	var g errgroup.Group
	g.Go(func() error { m.runGitDorker(ctx, in.Domain, gitdorkerPath); return nil })
	g.Go(func() error { m.runTrufflehogGithub(ctx, in.OrgName, trufflehogPath); return nil })
	g.Go(func() error { m.runMetafinder(ctx, in.Domain, metadataPath); return nil })
	g.Go(func() error { m.runGitWildHunt(ctx, in.OrgName, gitWildHuntPath); return nil })
	g.Go(func() error { m.discoverGitlab(ctx, in.Domain, gitlabPath); return nil })
	g.Wait()

	return modules.Output{
		Files: map[string]string{
			"gitdorker_results":     gitdorkerPath,
			"trufflehog_target":     trufflehogPath,
			"metadata":              metadataPath,
			"git_wild_hunt_results": gitWildHuntPath,
			"gitlab_discovery":      gitlabPath,
		},
		Summary: fmt.Sprintf("github/source intel for domain=%q org=%q", in.Domain, in.OrgName),
	}, nil
}

func (m *Module) runGitDorker(ctx context.Context, domain, outPath string) {
	if m.cfg.APIKeys.GithubToken == "" || m.cfg.Wordlists.GithubDorks == "" || domain == "" {
		warn("api_keys.github_token, wordlists.github_dorks and domain are required for GitDorker, skipping")
		return
	}
	bin, ok := runner.FirstInstalled("gitdorker", "GitDorker")
	if !ok {
		warn("GitDorker not found on PATH (continuing), skipping")
		return
	}
	args := []string{"-tf", m.cfg.APIKeys.GithubToken, "-q", domain, "-d", m.cfg.Wordlists.GithubDorks, "-o", outPath}
	if _, err := m.run.Run(ctx, bin, args, nil); err != nil {
		warn("GitDorker failed (continuing): %v", err)
	}
}

func (m *Module) runTrufflehogGithub(ctx context.Context, orgName, outPath string) {
	if orgName == "" || m.cfg.APIKeys.GithubToken == "" {
		warn("org_name and api_keys.github_token are required for trufflehog github, skipping")
		return
	}
	args := []string{
		"github", "--org=" + orgName, "--token=" + m.cfg.APIKeys.GithubToken,
		"--only-verified", "--threads=20", "--json",
	}
	result, err := m.run.Run(ctx, "trufflehog", args, nil)
	if err != nil {
		warn("trufflehog github failed (continuing): %v", err)
		return
	}
	if err := os.WriteFile(outPath, []byte(result.Stdout), 0o644); err != nil {
		warn("writing trufflehog_target.json (continuing): %v", err)
	}
}

func (m *Module) runMetafinder(ctx context.Context, domain, outPath string) {
	if domain == "" {
		return
	}
	if err := runner.EnsureInstalled("metafinder"); err != nil {
		warn("metafinder not found on PATH (continuing), skipping")
		return
	}
	args := []string{"-d", domain, "-l", "10", "-go", "-bi", "-ba", "-o", outPath}
	if _, err := m.run.Run(ctx, "metafinder", args, nil); err != nil {
		warn("metafinder failed (continuing): %v", err)
	}
}

func (m *Module) runGitWildHunt(ctx context.Context, orgName, outPath string) {
	if orgName == "" {
		return
	}
	bin, ok := runner.FirstInstalled("git-wild-hunt", "gitwildhunt")
	if !ok {
		warn("git-wild-hunt not found on PATH (continuing), skipping")
		return
	}
	query := fmt.Sprintf("org:%s extension:json filename:creds", orgName)
	result, err := m.run.Run(ctx, bin, []string{"-s", query}, nil)
	if err != nil {
		warn("git-wild-hunt failed (continuing): %v", err)
		return
	}
	if err := os.WriteFile(outPath, []byte(result.Stdout), 0o644); err != nil {
		warn("writing git_wild_hunt_results.txt (continuing): %v", err)
	}
}

// discoverGitlab probes candidate subdomains of a private GitLab
// (gitlab./git./code.{domain}), and runs gitleaks against it if it responds
// without authentication.
func (m *Module) discoverGitlab(ctx context.Context, domain, outPath string) {
	if domain == "" {
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	var lines []string
	for _, prefix := range []string{"gitlab", "git", "code"} {
		host := prefix + "." + domain
		url := "https://" + host
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 0 || resp.StatusCode >= 500 {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s [%d]", url, resp.StatusCode))

		result, err := m.run.Run(ctx, "gitleaks", []string{"detect", "--source", url, "-v"}, nil)
		if err != nil {
			warn("gitleaks on %s failed (continuing): %v", url, err)
			continue
		}
		lines = append(lines, splitNonEmpty(result.Stdout)...)
	}
	if err := writeLines(outPath, lines); err != nil {
		warn("writing gitlab_discovery.txt (continuing): %v", err)
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
	fmt.Fprintf(os.Stderr, "githubintel: "+format+"\n", args...)
}
