// Package target serializes the content of a recon (as opposed to its
// execution, covered by internal/state) into three files under
// targets/<name>/: recon.json (machine snapshot), functionality_map.json
// (functional map derived from the liveness and URL-discovery modules) and
// findings.md (human summary).
//
// Rather than requiring a rich typed struct from every module (modules.Output
// is deliberately thin: Files/Summary/Count), target is built from three
// already-available sources — the scope from config.Config, the entries of
// state.State (status + summary + logical Files map per module) and the
// output files referenced by that map, read generically (line counts,
// samples, tech_stack pass-through). No filename is hardcoded here: target
// only knows stable logical keys (all_subs, alive_subs, js_urls...), the ones
// modules already put in Output.Files. A module that renames its output file
// does not affect target as long as the logical key is unchanged.
//
// Warn-and-continue: a referenced but absent/unreadable file is not an error
// (Lines = -1, empty sample), consistent with the rest of the pipeline where
// a partially scanned target is the normal state.
package target

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/state"
)

// Names of the files produced in output_dir (= targets/<name>/).
const (
	ReconFile            = "recon.json"
	FunctionalityMapFile = "functionality_map.json"
	FindingsFile         = "findings.md"
)

// sampleSize bounds the number of sample lines kept per file in
// functionality_map.json: enough to judge the content, not enough to copy
// thousands of URLs (same principle as the MCP summaries).
const sampleSize = 10

// Logical keys (Output.Files) used to derive the asset counters of
// recon.json. Documented in one place: if a module adds a relevant output,
// extend this.
var assetKeys = struct {
	subdomains, aliveHosts, urls, vhosts, originIPs, takeover string
}{
	subdomains: "all_subs",
	aliveHosts: "alive_subs",
	urls:       "all_urls",
	vhosts:     "vhosts_found",
	originIPs:  "origin_ip_candidates",
	takeover:   "takeover_candidates",
}

// urlCategoryKeys are the logical keys of the categorized URL files produced
// by the URL-discovery module, carried over as-is into
// functionality_map.json. Fixed order for deterministic output.
var urlCategoryKeys = []string{
	"js_urls", "api_urls", "admin_urls", "auth_urls", "upload_urls",
	"sensitive_urls", "idor_candidates", "redirect_urls", "cloud_creds_urls",
}

// FileData is the in-memory view of an output file referenced by a module.
// Produced by a reader (injected, so the builders stay testable without
// disk).
type FileData struct {
	Lines  int      // number of non-empty lines; -1 if absent/unreadable
	Sample []string // up to sampleSize first non-empty lines
	Raw    []byte   // raw content (used for the tech_stack pass-through)
	Err    error    // non-nil if the file could not be read
}

// Reader reads an output file. diskReader is the real implementation; tests
// inject a fake one.
type Reader func(path string) FileData

// diskReader reads a file from disk. A missing file is not a fatal error:
// Lines = -1, the rest empty.
func diskReader(path string) FileData {
	f, err := os.Open(path)
	if err != nil {
		return FileData{Lines: -1, Err: err}
	}
	defer f.Close()

	raw, _ := os.ReadFile(path)
	fd := FileData{Lines: 0, Raw: raw}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fd.Lines++
		if len(fd.Sample) < sampleSize {
			fd.Sample = append(fd.Sample, line)
		}
	}
	if err := sc.Err(); err != nil {
		return FileData{Lines: -1, Err: err}
	}
	return fd
}

// --- recon.json -------------------------------------------------------------

type ReconReport struct {
	Target      string         `json:"target"`
	OrgName     string         `json:"org_name,omitempty"`
	GeneratedAt time.Time      `json:"generated_at"`
	Modules     []ModuleReport `json:"modules"`
	Assets      Assets         `json:"assets"`
}

type ModuleReport struct {
	ID         string       `json:"id"`     // "M1", "M3", "MB"...
	Module     string       `json:"module"` // technical name (passive, infra...)
	Status     string       `json:"status"` // done|failed|running|interrupted|pending
	Summary    string       `json:"summary,omitempty"`
	Error      string       `json:"error,omitempty"`
	StartedAt  *time.Time   `json:"started_at,omitempty"`
	FinishedAt *time.Time   `json:"finished_at,omitempty"`
	Files      []FileReport `json:"files,omitempty"`
}

type FileReport struct {
	Name  string `json:"name"` // logical key
	Path  string `json:"path"`
	Lines int    `json:"lines"` // -1 if absent/unreadable
}

// Assets aggregates cross-cutting asset counters, derived from the logical
// keys in assetKeys. A counter stays 0 if the corresponding module has not
// (yet) run.
type Assets struct {
	Subdomains         int `json:"subdomains"`
	AliveHosts         int `json:"alive_hosts"`
	URLs               int `json:"urls"`
	Vhosts             int `json:"vhosts"`
	OriginIPCandidates int `json:"origin_ip_candidates"`
	TakeoverCandidates int `json:"takeover_candidates"`
}

// statusPending is the synthetic status of a roadmap module with no entry in
// state.json (never run for this target).
const statusPending = "pending"

// BuildReport builds the recon.json snapshot. Deterministic for a given state
// and reader (modules in state.Roadmap order), so testable without disk.
func BuildReport(cfg *config.Config, st *state.State, read Reader) ReconReport {
	rep := ReconReport{
		Target:      cfg.Scope.Domain,
		OrgName:     cfg.Scope.OrgName,
		GeneratedAt: time.Now().UTC(),
	}

	// lineCache ensures each file is read once, whether it serves a
	// ModuleReport or an Assets counter.
	lineCache := map[string]int{}
	countOf := func(path string) int {
		if n, ok := lineCache[path]; ok {
			return n
		}
		n := read(path).Lines
		lineCache[path] = n
		return n
	}

	// assetPaths collects, per logical asset key, the path seen in the state.
	assetPaths := map[string]string{}

	for _, rm := range state.Roadmap {
		mr := ModuleReport{ID: rm.ID, Module: rm.Module, Status: statusPending}
		if e, ok := st.Entries[rm.Module]; ok {
			mr.Status = string(e.Status)
			mr.Summary = e.Summary
			mr.Error = e.Error
			if !e.StartedAt.IsZero() {
				t := e.StartedAt
				mr.StartedAt = &t
			}
			if !e.FinishedAt.IsZero() {
				t := e.FinishedAt
				mr.FinishedAt = &t
			}
			for _, name := range sortedKeys(e.Files) {
				path := e.Files[name]
				mr.Files = append(mr.Files, FileReport{Name: name, Path: path, Lines: countOf(path)})
				assetPaths[name] = path
			}
		}
		rep.Modules = append(rep.Modules, mr)
	}

	asset := func(key string) int {
		if p, ok := assetPaths[key]; ok {
			if n := countOf(p); n > 0 {
				return n
			}
		}
		return 0
	}
	rep.Assets = Assets{
		Subdomains:         asset(assetKeys.subdomains),
		AliveHosts:         asset(assetKeys.aliveHosts),
		URLs:               asset(assetKeys.urls),
		Vhosts:             asset(assetKeys.vhosts),
		OriginIPCandidates: asset(assetKeys.originIPs),
		TakeoverCandidates: asset(assetKeys.takeover),
	}
	return rep
}

// --- functionality_map.json -------------------------------------------------

type FunctionalityMap struct {
	Target        string                 `json:"target"`
	GeneratedAt   time.Time              `json:"generated_at"`
	AliveHosts    int                    `json:"alive_hosts"`
	TechStack     json.RawMessage        `json:"tech_stack,omitempty"`
	URLCategories map[string]URLCategory `json:"url_categories,omitempty"`
}

type URLCategory struct {
	Count  int      `json:"count"`
	Sample []string `json:"sample,omitempty"`
}

// BuildFunctionalityMap derives the functional map from the liveness module
// (tech_stack, alive_subs) and the URL-discovery module (categorized URLs).
// Logical keys absent from the state (modules not run) are simply omitted.
func BuildFunctionalityMap(cfg *config.Config, st *state.State, read Reader) FunctionalityMap {
	fm := FunctionalityMap{
		Target:      cfg.Scope.Domain,
		GeneratedAt: time.Now().UTC(),
	}

	// Paths per logical key, across all modules.
	paths := map[string]string{}
	for _, e := range st.Entries {
		for name, p := range e.Files {
			paths[name] = p
		}
	}

	if p, ok := paths[assetKeys.aliveHosts]; ok {
		if n := read(p).Lines; n > 0 {
			fm.AliveHosts = n
		}
	}
	if p, ok := paths["tech_stack"]; ok {
		if fd := read(p); fd.Err == nil && json.Valid(fd.Raw) {
			fm.TechStack = json.RawMessage(fd.Raw)
		}
	}
	for _, key := range urlCategoryKeys {
		p, ok := paths[key]
		if !ok {
			continue
		}
		fd := read(p)
		if fd.Lines < 0 {
			continue
		}
		fm.URLCategories = ensureMap(fm.URLCategories)
		fm.URLCategories[key] = URLCategory{Count: fd.Lines, Sample: fd.Sample}
	}
	return fm
}

// --- findings.md ------------------------------------------------------------

// RenderFindings produces the human summary. Pure (reads nothing): it only
// formats an already-built ReconReport and FunctionalityMap.
func RenderFindings(rep ReconReport, fm FunctionalityMap) string {
	var b strings.Builder
	title := rep.Target
	if title == "" {
		title = "(no domain set)"
	}
	fmt.Fprintf(&b, "# Findings — %s\n\n", title)
	if rep.OrgName != "" {
		fmt.Fprintf(&b, "**Organization:** %s\n\n", rep.OrgName)
	}
	fmt.Fprintf(&b, "_Generated on %s (UTC)._\n\n", rep.GeneratedAt.Format("2006-01-02 15:04"))

	b.WriteString("## Assets\n\n")
	fmt.Fprintf(&b, "- Subdomains: **%d**\n", rep.Assets.Subdomains)
	fmt.Fprintf(&b, "- Alive hosts: **%d**\n", rep.Assets.AliveHosts)
	fmt.Fprintf(&b, "- URLs discovered: **%d**\n", rep.Assets.URLs)
	fmt.Fprintf(&b, "- Vhosts: **%d**\n", rep.Assets.Vhosts)
	fmt.Fprintf(&b, "- Origin IP candidates: **%d**\n", rep.Assets.OriginIPCandidates)
	fmt.Fprintf(&b, "- Takeover candidates: **%d**\n\n", rep.Assets.TakeoverCandidates)

	b.WriteString("## Modules\n\n")
	b.WriteString("| Module | Status | Summary |\n|---|---|---|\n")
	for _, m := range rep.Modules {
		summary := m.Summary
		if m.Status == "failed" && m.Error != "" {
			summary = m.Error
		}
		fmt.Fprintf(&b, "| %s %s | %s | %s |\n", m.ID, m.Module, m.Status, mdCell(summary))
	}
	b.WriteString("\n")

	// Signals to review first: the sensitive URL categories.
	highlights := []string{"sensitive_urls", "cloud_creds_urls", "admin_urls", "idor_candidates"}
	var shown bool
	for _, key := range highlights {
		cat, ok := fm.URLCategories[key]
		if !ok || cat.Count == 0 {
			continue
		}
		if !shown {
			b.WriteString("## Review first (URLs)\n\n")
			shown = true
		}
		fmt.Fprintf(&b, "### %s (%d)\n\n", key, cat.Count)
		for _, s := range cat.Sample {
			fmt.Fprintf(&b, "- `%s`\n", s)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// Artifacts lists the paths of the files written by Write.
type Artifacts struct {
	Recon            string
	FunctionalityMap string
	Findings         string
}

// Build constructs the report and functional map from disk (real reader),
// without writing anything. Useful to expose counters/statuses (e.g. MCP
// handlers recon_status / recon_report) without re-reading files or
// duplicating the aggregation logic.
func Build(cfg *config.Config, st *state.State) (ReconReport, FunctionalityMap) {
	return BuildReport(cfg, st, diskReader), BuildFunctionalityMap(cfg, st, diskReader)
}

// Write builds the three artifacts and writes them into cfg.OutputDir. Uses
// the real disk reader. Call once a recon (or part of one) is done; it uses
// whatever state.json contains at that moment.
func Write(cfg *config.Config, st *state.State) (Artifacts, error) {
	return write(cfg, st, diskReader)
}

// write isolates reader injection for tests.
func write(cfg *config.Config, st *state.State, read Reader) (Artifacts, error) {
	dir := cfg.OutputDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Artifacts{}, err
	}

	rep := BuildReport(cfg, st, read)
	fm := BuildFunctionalityMap(cfg, st, read)
	findings := RenderFindings(rep, fm)

	art := Artifacts{
		Recon:            filepath.Join(dir, ReconFile),
		FunctionalityMap: filepath.Join(dir, FunctionalityMapFile),
		Findings:         filepath.Join(dir, FindingsFile),
	}
	if err := writeJSON(art.Recon, rep); err != nil {
		return art, err
	}
	if err := writeJSON(art.FunctionalityMap, fm); err != nil {
		return art, err
	}
	if err := os.WriteFile(art.Findings, []byte(findings), 0o644); err != nil {
		return art, err
	}
	return art, nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// --- helpers ----------------------------------------------------------------

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func ensureMap(m map[string]URLCategory) map[string]URLCategory {
	if m == nil {
		return map[string]URLCategory{}
	}
	return m
}

// mdCell neutralizes pipes and newlines so they do not break a Markdown table
// cell.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}
