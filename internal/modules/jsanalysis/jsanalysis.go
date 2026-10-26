// Package jsanalysis implements JavaScript analysis for leaked secrets. Every
// branch (subjs, jsleak, lazyegg, source maps, trufflehog filesystem)
// consumes only js_urls.txt (output of urldiscovery) and is independent of
// the others: they run in parallel. lazyegg is a Python script (see
// config.ToolPath("lazyegg")).
package jsanalysis

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/runner"
)

const Name = "jsanalysis"

type Module struct {
	cfg *config.Config
	run *runner.Runner
}

func New(cfg *config.Config, r *runner.Runner) *Module {
	return &Module{cfg: cfg, run: r}
}

func (m *Module) Name() string { return Name }

// DependsOn: consumes js_urls.txt, the JS category of urldiscovery.
func (m *Module) DependsOn() []string { return []string{"urldiscovery"} }

func (m *Module) Run(ctx context.Context, in modules.Input) (modules.Output, error) {
	jsURLsPath := filepath.Join(in.OutputDir, "js_urls.txt")
	urls := readLines(jsURLsPath)
	if len(urls) == 0 {
		return modules.Output{}, modules.NoInput(fmt.Sprintf("jsanalysis: %s is empty or missing (run urldiscovery first)", jsURLsPath))
	}

	downloadDir := filepath.Join(in.OutputDir, "js_downloaded")
	sourcemapsDir := filepath.Join(in.OutputDir, "sourcemaps")
	jsFilesPath := filepath.Join(in.OutputDir, "js_files.txt")
	jsleakPath := filepath.Join(in.OutputDir, "jsleak_output.txt")
	lazyeggPath := filepath.Join(in.OutputDir, "lazyegg_output.txt")
	secretsPath := filepath.Join(in.OutputDir, "secrets_found.json")

	var g errgroup.Group
	g.Go(func() error { m.runSubjs(ctx, urls, jsFilesPath); return nil })
	g.Go(func() error {
		m.runPerURL(ctx, "jsleak", urls, []string{"-s", "-l", "-k", "-e"}, jsleakPath)
		return nil
	})
	g.Go(func() error { m.runLazyegg(ctx, urls, lazyeggPath); return nil })
	var mapsFound int
	g.Go(func() error { mapsFound = m.fetchSourceMaps(ctx, urls, sourcemapsDir); return nil })
	g.Wait()

	// trufflehog needs the JS files on disk: downloaded after the branches
	// above (independent of them, but we reuse the same URLs without a second
	// HTTP pass), then scanned.
	downloaded := m.downloadJS(ctx, urls, downloadDir)
	m.runTrufflehogFS(ctx, downloadDir, secretsPath)

	return modules.Output{
		Files: map[string]string{
			"js_files":      jsFilesPath,
			"jsleak":        jsleakPath,
			"lazyegg":       lazyeggPath,
			"sourcemaps":    sourcemapsDir,
			"secrets":       secretsPath,
			"js_downloaded": downloadDir,
		},
		Summary: fmt.Sprintf("%d JS URLs analyzed, %d downloaded, %d source maps found", len(urls), downloaded, mapsFound),
		Count:   len(urls),
	}, nil
}

func (m *Module) runSubjs(ctx context.Context, urls []string, outPath string) {
	result, err := m.run.RunWithInput(ctx, "subjs", nil, strings.Join(urls, "\n"), nil)
	if err != nil {
		warn("subjs failed (continuing): %v", err)
		return
	}
	if err := writeLines(outPath, splitNonEmpty(result.Stdout)); err != nil {
		warn("writing js_files.txt (continuing): %v", err)
	}
}

// runPerURL runs `bin flags... <url>` for each URL, bounded by
// ThreadsFor(Name).
func (m *Module) runPerURL(ctx context.Context, bin string, urls []string, flags []string, outPath string) {
	lines := m.forEachURL(ctx, urls, func(ctx context.Context, url string) string {
		result, err := m.run.Run(ctx, bin, append(append([]string{}, flags...), url), nil)
		if err != nil {
			warn("%s on %s failed (continuing): %v", bin, url, err)
			return ""
		}
		return result.Stdout
	})
	if err := writeLines(outPath, lines); err != nil {
		warn("writing %s (continuing): %v", filepath.Base(outPath), err)
	}
}

func (m *Module) runLazyegg(ctx context.Context, urls []string, outPath string) {
	scriptPath, ok := m.cfg.ToolPath("lazyegg")
	if !ok {
		warn("tool_paths.lazyegg not configured, skipping")
		return
	}
	lines := m.forEachURL(ctx, urls, func(ctx context.Context, url string) string {
		bin, args, _ := runner.PythonScript(scriptPath, []string{url, "--js_urls", "--domains", "--ips"})
		result, err := m.run.Run(ctx, bin, args, nil)
		if err != nil {
			warn("lazyegg on %s failed (continuing): %v", url, err)
			return ""
		}
		return result.Stdout
	})
	if err := writeLines(outPath, lines); err != nil {
		warn("writing lazyegg_output.txt (continuing): %v", err)
	}
}

// fetchSourceMaps tries `{url}.map` over direct HTTP: a source map left
// enabled in production exposes the un-minified source.
func (m *Module) fetchSourceMaps(ctx context.Context, urls []string, sourcemapsDir string) int {
	client := &http.Client{Timeout: 15 * time.Second}
	var found int
	m.forEachURL(ctx, urls, func(ctx context.Context, url string) string {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+".map", nil)
		if err != nil {
			return ""
		}
		resp, err := client.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return ""
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil || len(body) == 0 {
			return ""
		}
		if err := os.MkdirAll(sourcemapsDir, 0o755); err != nil {
			return ""
		}
		path := filepath.Join(sourcemapsDir, hashName(url)+".map")
		if err := os.WriteFile(path, body, 0o644); err == nil {
			found++
		}
		return ""
	})
	return found
}

// downloadJS fetches each JS file's content for the trufflehog filesystem
// scan (which needs local files, not URLs).
func (m *Module) downloadJS(ctx context.Context, urls []string, downloadDir string) int {
	client := &http.Client{Timeout: 15 * time.Second}
	var downloaded int
	m.forEachURL(ctx, urls, func(ctx context.Context, url string) string {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return ""
		}
		resp, err := client.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return ""
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil || len(body) == 0 {
			return ""
		}
		if err := os.MkdirAll(downloadDir, 0o755); err != nil {
			return ""
		}
		path := filepath.Join(downloadDir, hashName(url)+".js")
		if err := os.WriteFile(path, body, 0o644); err == nil {
			downloaded++
		}
		return ""
	})
	return downloaded
}

func (m *Module) runTrufflehogFS(ctx context.Context, downloadDir, outPath string) {
	if _, err := os.Stat(downloadDir); err != nil {
		return // nothing downloaded, no point calling trufflehog
	}
	result, err := m.run.Run(ctx, "trufflehog", []string{"filesystem", downloadDir, "--json"}, nil)
	if err != nil {
		warn("trufflehog filesystem failed (continuing): %v", err)
		return
	}
	if err := os.WriteFile(outPath, []byte(result.Stdout), 0o644); err != nil {
		warn("writing secrets_found.json (continuing): %v", err)
	}
}

// forEachURL applies fn to each URL, bounded by ThreadsFor(Name), and returns
// the non-empty outputs. Used by every per-URL branch of this module to avoid
// repeating the pool logic.
func (m *Module) forEachURL(ctx context.Context, urls []string, fn func(ctx context.Context, url string) string) []string {
	threads := m.cfg.ThreadsFor(Name)
	if threads <= 0 {
		threads = 20
	}
	sem := make(chan struct{}, threads)

	var mu sync.Mutex
	var out []string
	var g errgroup.Group
	for _, url := range urls {
		url := url
		g.Go(func() error {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return nil
			}
			defer func() { <-sem }()
			res := fn(ctx, url)
			if res = strings.TrimSpace(res); res != "" {
				mu.Lock()
				out = append(out, res)
				mu.Unlock()
			}
			return nil
		})
	}
	g.Wait()
	return out
}

func hashName(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func readLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return splitNonEmpty(string(data))
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
	fmt.Fprintf(os.Stderr, "jsanalysis: "+format+"\n", args...)
}
