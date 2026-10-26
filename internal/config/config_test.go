package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ResolvesRelativePathsAgainstConfigDir(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "recon.config.yaml")
	body := `scope:
  domain: demo.test
wordlists:
  dns: wl/dns.txt
  web: /abs/web.txt
resolvers: ../shared/resolvers.txt
tool_paths:
  favup: scripts/favUp.py
  webanalyze_apps: /opt/webanalyze/technologies.json
  tilde: ~/.config/webanalyze/technologies.json
output_dir: ../../targets/demo/
`
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Relative -> resolved against the config file's directory.
	if want := filepath.Join(dir, "wl/dns.txt"); cfg.Wordlists.DNS != want {
		t.Errorf("dns = %q, want %q", cfg.Wordlists.DNS, want)
	}
	if want := filepath.Join(dir, "../../targets/demo"); cfg.OutputDir != want {
		t.Errorf("output_dir = %q, want %q", cfg.OutputDir, want)
	}
	if want := filepath.Join(dir, "scripts/favUp.py"); cfg.ToolPaths["favup"] != want {
		t.Errorf("favup = %q, want %q", cfg.ToolPaths["favup"], want)
	}
	// Already absolute -> unchanged.
	if cfg.Wordlists.Web != "/abs/web.txt" {
		t.Errorf("web (absolute) modified: %q", cfg.Wordlists.Web)
	}

	// ~ expanded to the user's home.
	home, _ := os.UserHomeDir()
	if want := filepath.Join(home, ".config/webanalyze/technologies.json"); cfg.ToolPaths["tilde"] != want {
		t.Errorf("tilde = %q, want %q", cfg.ToolPaths["tilde"], want)
	}
	if cfg.ToolPaths["webanalyze_apps"] != "/opt/webanalyze/technologies.json" {
		t.Errorf("webanalyze_apps (absolute) modified: %q", cfg.ToolPaths["webanalyze_apps"])
	}
	// Every resolved path is absolute.
	for _, p := range []string{cfg.OutputDir, cfg.Resolvers, cfg.Wordlists.DNS, cfg.ToolPaths["favup"]} {
		if !filepath.IsAbs(p) {
			t.Errorf("path not absolute after resolution: %q", p)
		}
	}
}
