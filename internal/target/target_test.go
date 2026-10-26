package target

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/state"
)

// fakeReader serves in-memory FileData indexed by path, to test the builders
// without touching disk.
func fakeReader(files map[string]FileData) Reader {
	return func(path string) FileData {
		if fd, ok := files[path]; ok {
			return fd
		}
		return FileData{Lines: -1, Err: os.ErrNotExist}
	}
}

func newState(t *testing.T, entries map[string]state.Entry) *state.State {
	t.Helper()
	dir := t.TempDir()
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	for name, e := range entries {
		st.Entries[name] = e
	}
	return st
}

func baseCfg() *config.Config {
	return &config.Config{Scope: config.Scope{Domain: "example.com", OrgName: "Example Inc"}}
}

func TestBuildReport_AssetsAndOrdering(t *testing.T) {
	st := newState(t, map[string]state.Entry{
		"passive":       {Status: state.StatusDone, Summary: "12 subs", Files: map[string]string{"subs_passive": "/o/subs_passive.txt"}},
		"merge_resolve": {Status: state.StatusDone, Files: map[string]string{"all_subs": "/o/all_subs.txt"}},
		"alive":         {Status: state.StatusDone, Files: map[string]string{"alive_subs": "/o/alive.txt", "tech_stack": "/o/tech.json"}},
		"takeover":      {Status: state.StatusFailed, Error: "subzy missing", Files: map[string]string{"takeover_candidates": "/o/takeover.txt"}},
	})
	read := fakeReader(map[string]FileData{
		"/o/all_subs.txt":     {Lines: 50},
		"/o/alive.txt":        {Lines: 20},
		"/o/takeover.txt":     {Lines: 2},
		"/o/subs_passive.txt": {Lines: 12},
	})

	rep := BuildReport(baseCfg(), st, read)

	if rep.Target != "example.com" || rep.OrgName != "Example Inc" {
		t.Fatalf("scope not propagated: %+v", rep)
	}
	// Every roadmap module present, in order.
	if len(rep.Modules) != len(state.Roadmap) {
		t.Fatalf("got %d modules, want %d", len(rep.Modules), len(state.Roadmap))
	}
	if rep.Modules[0].ID != "M1" || rep.Modules[0].Module != "passive" {
		t.Fatalf("first module = %+v, want M1/passive", rep.Modules[0])
	}
	// A module that did not run is "pending".
	byMod := map[string]ModuleReport{}
	for _, m := range rep.Modules {
		byMod[m.Module] = m
	}
	if byMod["infra"].Status != statusPending {
		t.Errorf("infra status = %q, want pending", byMod["infra"].Status)
	}
	if byMod["takeover"].Status != "failed" || byMod["takeover"].Error != "subzy missing" {
		t.Errorf("takeover entry wrong: %+v", byMod["takeover"])
	}
	if got := rep.Assets; got.Subdomains != 50 || got.AliveHosts != 20 || got.TakeoverCandidates != 2 {
		t.Errorf("assets = %+v, want subs 50 / alive 20 / takeover 2", got)
	}
	if rep.Assets.URLs != 0 || rep.Assets.Vhosts != 0 {
		t.Errorf("absent assets should be 0, got %+v", rep.Assets)
	}
}

func TestBuildReport_MissingFileGivesNegativeLinesAndZeroAsset(t *testing.T) {
	st := newState(t, map[string]state.Entry{
		"merge_resolve": {Status: state.StatusDone, Files: map[string]string{"all_subs": "/gone.txt"}},
	})
	rep := BuildReport(baseCfg(), st, fakeReader(nil)) // reader returns -1 for everything

	var merge ModuleReport
	for _, m := range rep.Modules {
		if m.Module == "merge_resolve" {
			merge = m
		}
	}
	if len(merge.Files) != 1 || merge.Files[0].Lines != -1 {
		t.Fatalf("missing file should report Lines -1, got %+v", merge.Files)
	}
	if rep.Assets.Subdomains != 0 {
		t.Errorf("missing all_subs should give 0 subdomains, got %d", rep.Assets.Subdomains)
	}
}

func TestBuildFunctionalityMap(t *testing.T) {
	st := newState(t, map[string]state.Entry{
		"alive": {Status: state.StatusDone, Files: map[string]string{
			"alive_subs": "/o/alive.txt", "tech_stack": "/o/tech.json"}},
		"urldiscovery": {Status: state.StatusDone, Files: map[string]string{
			"all_urls":   "/o/all_urls.txt",
			"js_urls":    "/o/js.txt",
			"admin_urls": "/o/admin.txt",
		}},
	})
	read := fakeReader(map[string]FileData{
		"/o/alive.txt": {Lines: 7},
		"/o/tech.json": {Raw: []byte(`{"example.com":{"server":"nginx"}}`)},
		"/o/js.txt":    {Lines: 3, Sample: []string{"https://a/1.js", "https://a/2.js"}},
		"/o/admin.txt": {Lines: 1, Sample: []string{"https://a/admin"}},
	})

	fm := BuildFunctionalityMap(baseCfg(), st, read)

	if fm.AliveHosts != 7 {
		t.Errorf("alive hosts = %d, want 7", fm.AliveHosts)
	}
	if !json.Valid(fm.TechStack) || !strings.Contains(string(fm.TechStack), "nginx") {
		t.Errorf("tech stack pass-through wrong: %s", fm.TechStack)
	}
	if fm.URLCategories["js_urls"].Count != 3 || len(fm.URLCategories["js_urls"].Sample) != 2 {
		t.Errorf("js_urls category wrong: %+v", fm.URLCategories["js_urls"])
	}
	if _, ok := fm.URLCategories["api_urls"]; ok {
		t.Errorf("api_urls absent from state should not appear")
	}
}

func TestBuildFunctionalityMap_InvalidTechStackIgnored(t *testing.T) {
	st := newState(t, map[string]state.Entry{
		"alive": {Status: state.StatusDone, Files: map[string]string{"tech_stack": "/o/tech.json"}},
	})
	read := fakeReader(map[string]FileData{"/o/tech.json": {Raw: []byte("not json")}})
	fm := BuildFunctionalityMap(baseCfg(), st, read)
	if fm.TechStack != nil {
		t.Errorf("invalid tech_stack should be dropped, got %s", fm.TechStack)
	}
}

func TestRenderFindings(t *testing.T) {
	rep := ReconReport{
		Target:      "example.com",
		OrgName:     "Example Inc",
		GeneratedAt: time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC),
		Modules: []ModuleReport{
			{ID: "M1", Module: "passive", Status: "done", Summary: "12 subs"},
			{ID: "M13", Module: "takeover", Status: "failed", Error: "pipe|broke\nhard"},
		},
		Assets: Assets{Subdomains: 12, AliveHosts: 5, TakeoverCandidates: 1},
	}
	fm := FunctionalityMap{URLCategories: map[string]URLCategory{
		"sensitive_urls": {Count: 2, Sample: []string{"https://a/.env"}},
	}}

	out := RenderFindings(rep, fm)

	for _, want := range []string{
		"# Findings — example.com",
		"Example Inc",
		"Subdomains: **12**",
		"M1 passive",
		"sensitive_urls (2)",
		"`https://a/.env`",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("findings missing %q\n---\n%s", want, out)
		}
	}
	// The error's pipes/newlines must not break the table cell.
	if strings.Contains(out, "pipe|broke") || strings.Contains(out, "broke\nhard") {
		t.Errorf("md cell not escaped:\n%s", out)
	}
}

func TestWrite_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := baseCfg()
	cfg.OutputDir = dir

	// A real file on disk to exercise diskReader via Write.
	allSubs := filepath.Join(dir, "all_subs.txt")
	if err := os.WriteFile(allSubs, []byte("a.example.com\n\nb.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, _ := state.Load(dir)
	st.Record("merge_resolve", time.Now(), time.Now(), modules.Output{
		Summary: "2 subs", Files: map[string]string{"all_subs": allSubs},
	}, nil)

	art, err := Write(cfg, st)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	for _, p := range []string{art.Recon, art.FunctionalityMap, art.Findings} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("artifact not written: %s (%v)", p, err)
		}
	}
	var rep ReconReport
	data, _ := os.ReadFile(art.Recon)
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("recon.json invalid: %v", err)
	}
	if rep.Assets.Subdomains != 2 {
		t.Errorf("round-trip subdomains = %d, want 2 (blank line ignored)", rep.Assets.Subdomains)
	}
}
