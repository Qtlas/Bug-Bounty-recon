// Package config loads and validates recon.config.yaml.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Scope             Scope             `yaml:"scope"`
	Wordlists         Wordlists         `yaml:"wordlists"`
	Resolvers         string            `yaml:"resolvers"`
	ScanProfile       string            `yaml:"scan_profile"`
	RateLimits        RateLimits        `yaml:"rate_limits"`
	BlockingDetection BlockingDetection `yaml:"blocking_detection"`
	APIKeys           APIKeys           `yaml:"api_keys"`
	Modules           ModulesToggle     `yaml:"modules"`
	ToolPaths         map[string]string `yaml:"tool_paths"`
	OutputDir         string            `yaml:"output_dir"`
}

type Scope struct {
	Domain  string `yaml:"domain"`
	OrgName string `yaml:"org_name"`
}

type Wordlists struct {
	DNS          string `yaml:"dns"`
	Web          string `yaml:"web"`
	GithubDorks  string `yaml:"github_dorks"`
	Permutations string `yaml:"permutations"` // optional; empty = built-in prefix list
}

type RateLimits struct {
	DefaultThreads        int                        `yaml:"default_threads"`
	DefaultRPS            int                        `yaml:"default_rps"`
	DefaultTimeoutMinutes int                        `yaml:"default_timeout_minutes"` // budget per external command (not the whole run)
	PerModule             map[string]ModuleRateLimit `yaml:"per_module"`
}

type ModuleRateLimit struct {
	Threads                int `yaml:"threads"`
	DelayBetweenRequestsMs int `yaml:"delay_between_requests_ms"`
	TimeoutMinutes         int `yaml:"timeout_minutes"`
	// Dedicated bounds for the slow external commands of the infra module
	// (see internal/modules/infra); only meaningful under per_module.infra.
	// 0/absent = the module's built-in default.
	MetabigorTimeoutMinutes int `yaml:"metabigor_timeout_minutes,omitempty"` // default 4
	PTRTimeoutMinutes       int `yaml:"ptr_timeout_minutes,omitempty"`       // default 10
	PTRMaxHostBits          int `yaml:"ptr_max_host_bits,omitempty"`         // default 16 (= /16)
}

// BlockingDetection configures the reaction to a run of consecutive 403/429
// (a WAF or rate-limit kicking in mid-scan).
type BlockingDetection struct {
	MaxConsecutive403 int     `yaml:"max_consecutive_403"`
	MaxConsecutive429 int     `yaml:"max_consecutive_429"`
	OnTrigger         string  `yaml:"on_trigger"` // pause_and_reduce | abort | alert_only
	PauseSeconds      int     `yaml:"pause_seconds"`
	ReduceFactor      float64 `yaml:"reduce_factor"`
}

type APIKeys struct {
	GithubToken  string `yaml:"github_token"`   // GitHub source intel
	ShodanAPIKey string `yaml:"shodan_api_key"` // favicon-hash origin lookups
	PDCPAPIKey   string `yaml:"pdcp_api_key"`   // ProjectDiscovery Cloud (asnmap requires it)
}

type ModulesToggle struct {
	DeepPassive  bool `yaml:"deep_passive"`  // add slower passive sources
	FullPorts    bool `yaml:"full_ports"`    // scan all 65535 ports instead of the top ports
	FastDirbrute bool `yaml:"fast_dirbrute"` // per-host fast directory bruteforce
}

// ToolPath returns the configured path for a tool that has no installable
// package (pip/go install) with a binary under a stable name on PATH: these
// are plain scripts, invoked via `python3 {tool_paths.<key>} ...`. Absent or
// empty key = not configured; the calling module warns-and-skips rather than
// guessing a path.
func (c *Config) ToolPath(key string) (string, bool) {
	path, ok := c.ToolPaths[key]
	if !ok || path == "" {
		return "", false
	}
	return path, true
}

// Load reads and parses the YAML config, then applies defaults for any unset
// field.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	cfg.applyDefaults()

	// Make the binary launchable from any working directory: relative paths
	// in the config are resolved against the config file's DIRECTORY, never
	// the current working directory.
	baseDir := filepath.Dir(path)
	if abs, err := filepath.Abs(baseDir); err == nil {
		baseDir = abs
	}
	cfg.resolvePaths(baseDir)
	return &cfg, nil
}

// resolvePaths makes every relative path in the config absolute, resolved
// against baseDir (the config file's directory). An already-absolute path or
// an empty (optional) field is left as-is.
func (c *Config) resolvePaths(baseDir string) {
	abs := func(p string) string {
		if p == "" {
			return p
		}
		// ~ and $VAR/${VAR}: makes configs portable across machines and users.
		if p == "~" || strings.HasPrefix(p, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				p = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/"))
			}
		}
		p = os.ExpandEnv(p)
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(baseDir, p)
	}
	c.OutputDir = abs(c.OutputDir)
	c.Resolvers = abs(c.Resolvers)
	c.Wordlists.DNS = abs(c.Wordlists.DNS)
	c.Wordlists.Web = abs(c.Wordlists.Web)
	c.Wordlists.GithubDorks = abs(c.Wordlists.GithubDorks)
	c.Wordlists.Permutations = abs(c.Wordlists.Permutations)
	for k, v := range c.ToolPaths {
		c.ToolPaths[k] = abs(v)
	}
}

func (c *Config) applyDefaults() {
	if c.ScanProfile == "" {
		c.ScanProfile = "normal"
	}
	if c.RateLimits.DefaultThreads == 0 {
		c.RateLimits.DefaultThreads = 50
	}
	if c.RateLimits.DefaultTimeoutMinutes == 0 {
		// 5 minutes is enough for lightweight passive sources, but a
		// bruteforce command over tens of thousands of entries far exceeds
		// that budget, hence a more generous default, adjustable per module
		// via rate_limits.per_module.<module>.timeout_minutes.
		c.RateLimits.DefaultTimeoutMinutes = 30
	}
	if c.BlockingDetection.MaxConsecutive403 == 0 {
		c.BlockingDetection.MaxConsecutive403 = 15
	}
	if c.BlockingDetection.MaxConsecutive429 == 0 {
		c.BlockingDetection.MaxConsecutive429 = 5
	}
	if c.BlockingDetection.OnTrigger == "" {
		c.BlockingDetection.OnTrigger = "pause_and_reduce"
	}
	if c.BlockingDetection.PauseSeconds == 0 {
		c.BlockingDetection.PauseSeconds = 60
	}
	if c.BlockingDetection.ReduceFactor == 0 {
		c.BlockingDetection.ReduceFactor = 0.5
	}
	if c.OutputDir == "" {
		c.OutputDir = "."
	}
}

// ThreadsFor returns the effective thread count for a given module: the
// scan_profile default, then the per_module override if any.
func (c *Config) ThreadsFor(module string) int {
	threads := c.RateLimits.DefaultThreads
	switch c.ScanProfile {
	case "stealth":
		threads = minInt(threads, 10)
	case "aggressive":
		threads = maxInt(threads, 100)
	}
	if override, ok := c.RateLimits.PerModule[module]; ok && override.Threads > 0 {
		threads = override.Threads
	}
	return threads
}

// TimeoutFor returns the effective time budget for an external command run by
// a given module: the default, then the per_module override if any. Applies
// per command (each call to runner.Run), not to the whole module.
func (c *Config) TimeoutFor(module string) time.Duration {
	minutes := c.RateLimits.DefaultTimeoutMinutes
	if override, ok := c.RateLimits.PerModule[module]; ok && override.TimeoutMinutes > 0 {
		minutes = override.TimeoutMinutes
	}
	return time.Duration(minutes) * time.Minute
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
