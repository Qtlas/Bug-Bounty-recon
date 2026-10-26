// Package state persists, per target (a state.json file in output_dir), which
// module ran, when, and with what result. It backs `recon-cli status`, which
// compares this file to the full roadmap to show what is done and what
// remains.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Qtlas/BugBounty-recon/internal/modules"
)

const fileName = "state.json"

type Status string

const (
	StatusDone   Status = "done"
	StatusFailed Status = "failed"
	// StatusRunning marks a module currently executing in the pipeline
	// (recon-cli scan), so `recon-cli status` reflects progress during a run,
	// not only once finished.
	StatusRunning Status = "running"
	// StatusInterrupted marks a module not (or no longer) running because the
	// scan was stopped (Ctrl+C / quit) before it started, or because one of
	// its dependencies failed.
	StatusInterrupted Status = "interrupted"
	// StatusSkipped marks a module that ran but had nothing to process (input
	// absent/empty because an upstream module produced nothing, see
	// modules.ErrNoInput). This is not a failure: distinct from StatusFailed
	// (a real crash) at triage time.
	StatusSkipped Status = "skipped"
)

type Entry struct {
	Status     Status            `json:"status"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at"`
	Summary    string            `json:"summary,omitempty"`
	Files      map[string]string `json:"files,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// State is indexed by module name (modules.Module.Name()), one entry per
// module: a rerun overwrites the previous result. mu protects Entries/Save:
// the pipeline (recon-cli scan) runs several modules concurrently, each
// updating this same State from its own goroutine.
type State struct {
	Entries map[string]Entry `json:"entries"`
	path    string
	mu      sync.Mutex
}

// Load reads <outputDir>/state.json. A missing file is not an error, it is
// the normal initial state of a never-scanned target.
func Load(outputDir string) (*State, error) {
	path := filepath.Join(outputDir, fileName)
	st := &State{Entries: make(map[string]Entry), path: path}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, st); err != nil {
		return nil, err
	}
	if st.Entries == nil {
		st.Entries = make(map[string]Entry)
	}
	st.path = path
	return st, nil
}

// Save persists the full state under s.mu: two modules finishing at the same
// time must never interleave their writes to state.json.
func (s *State) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o644)
}

// Record stores the result of a module run (success or failure). Does not
// call Save: the caller does that when ready to persist.
func (s *State) Record(module string, started, finished time.Time, out modules.Output, runErr error) {
	e := Entry{
		StartedAt:  started,
		FinishedAt: finished,
		Summary:    out.Summary,
		Files:      out.Files,
	}
	switch {
	case runErr == nil:
		e.Status = StatusDone
	case errors.Is(runErr, modules.ErrNoInput):
		// Nothing to process: a no-op, not a failure. The reason goes in
		// Summary (read as a benign note), Error stays empty.
		e.Status = StatusSkipped
		e.Summary = runErr.Error()
	default:
		e.Status = StatusFailed
		e.Error = runErr.Error()
	}
	s.setEntry(module, e)
}

// SetRunning marks a module as currently executing, so `recon-cli status`
// from another terminal sees progress live during a `recon-cli scan`.
func (s *State) SetRunning(module string, startedAt time.Time) {
	s.setEntry(module, Entry{Status: StatusRunning, StartedAt: startedAt})
}

// SetInterrupted marks a module that did not run (or did not finish) because
// of a pipeline stop (Ctrl+C / quit) or a failed dependency, with the reason
// in plain text.
func (s *State) SetInterrupted(module, reason string) {
	s.setEntry(module, Entry{Status: StatusInterrupted, Error: reason, FinishedAt: time.Now()})
}

func (s *State) setEntry(module string, e Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Entries == nil {
		s.Entries = make(map[string]Entry)
	}
	s.Entries[module] = e
}

// RoadmapEntry describes a module of the full plan, implemented or not, so
// that `recon-cli status` can also show modules that do not yet exist in
// internal/modules.
type RoadmapEntry struct {
	ID          string // "M1", "M2", "M3"...
	Module      string // name returned by modules.Module.Name(), once implemented
	Phase       string // short description, e.g. "passive_subdomain_enum"
	Implemented bool
}

// Roadmap is the dependency-graph order, not necessarily the real execution
// order once the concurrent pipeline is in place (several modules can run in
// parallel).
var Roadmap = []RoadmapEntry{
	{"M1", "passive", "passive_subdomain_enum", true},
	{"M2", "activebrute", "active_subdomain_bruteforce", true},
	{"M3", "infra", "infra_mapping", true},
	{"merge", "merge_resolve", "merge_and_resolve", true},
	{"M5", "alive", "alive_detection_and_fingerprint", true},
	{"M4", "originip", "origin_ip_discovery", true},
	{"M6", "vhost", "vhost_enum", true},
	{"M7", "urldiscovery", "url_endpoint_discovery", true},
	{"M8", "jsanalysis", "js_analysis_secrets", true},
	{"M9", "dirbrute", "dir_bruteforce_sensitive", true},
	{"M10", "githubintel", "github_source_intel", true},
	{"M11", "portscan", "port_scan_fingerprint", true},
	{"M13", "takeover", "subdomain_takeover_check", true},
	{"MB", "osintdork", "smart_osint_dorking", true},
}
