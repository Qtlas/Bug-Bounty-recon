// Package mcp exposes the recon modules as MCP tools (stdio transport). It is
// a thin transport layer: no handler holds business logic, each one reloads
// the config and reuses exactly the same execution path as recon-cli
// (pipeline.RunOne / pipeline.Run, internal/state, internal/target). CLI and
// MCP server share 100% of the code.
//
// Each handler returns a structured summary (status, counter, a sample via
// the files, paths) and never the full raw output — a module can emit
// thousands of lines that would flood the context.
package mcp

import (
	"context"
	"fmt"
	"path/filepath"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/pipeline"
	"github.com/Qtlas/BugBounty-recon/internal/state"
	"github.com/Qtlas/BugBounty-recon/internal/target"
)

const serverName = "recon-mcp"

// ModuleParams is the common input to the per-module tools. As for the CLI,
// the config is a YAML file edited once per target, with an optional
// domain/subs-file override at call time.
type ModuleParams struct {
	Config   string `json:"config,omitempty" jsonschema:"path to recon.config.yaml (default: recon.config.yaml)"`
	Domain   string `json:"domain,omitempty" jsonschema:"override of scope.domain read from the config"`
	SubsFile string `json:"subs_file,omitempty" jsonschema:"path to a subdomains file (default: <output_dir>/subs_passive.txt)"`
}

// ModuleResult is the summary returned by a module tool: never the raw
// content, only status + counter + paths of the produced files.
type ModuleResult struct {
	Module  string            `json:"module"`
	Status  string            `json:"status"` // done | failed
	Summary string            `json:"summary"`
	Count   int               `json:"count"`
	Files   map[string]string `json:"files,omitempty"`
}

// ConfigParams is the input to tools that do not target a specific module
// (status, report, scan without a selection).
type ConfigParams struct {
	Config string `json:"config,omitempty" jsonschema:"path to recon.config.yaml (default: recon.config.yaml)"`
	Domain string `json:"domain,omitempty" jsonschema:"override of scope.domain read from the config"`
}

// ScanParams adds module selection to ConfigParams.
type ScanParams struct {
	Config  string   `json:"config,omitempty" jsonschema:"path to recon.config.yaml (default: recon.config.yaml)"`
	Domain  string   `json:"domain,omitempty" jsonschema:"override of scope.domain read from the config"`
	Modules []string `json:"modules,omitempty" jsonschema:"subset of modules to run (default: all wired modules)"`
}

// ModuleStatus is the state of a module in a report/status.
type ModuleStatus struct {
	ID      string `json:"id"`     // M1, M3, MB...
	Module  string `json:"module"` // technical name
	Status  string `json:"status"` // done | failed | running | interrupted | pending
	Summary string `json:"summary,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Assets mirrors target.Assets (a flat type for a clean MCP output schema,
// without depending on the internal types).
type Assets struct {
	Subdomains         int `json:"subdomains"`
	AliveHosts         int `json:"alive_hosts"`
	URLs               int `json:"urls"`
	Vhosts             int `json:"vhosts"`
	OriginIPCandidates int `json:"origin_ip_candidates"`
	TakeoverCandidates int `json:"takeover_candidates"`
}

type StatusResult struct {
	Target      string         `json:"target"`
	ScanRunning bool           `json:"scan_running"`
	Modules     []ModuleStatus `json:"modules"`
	Assets      Assets         `json:"assets"`
}

type ReportResult struct {
	Target               string `json:"target"`
	ReconJSON            string `json:"recon_json"`
	FunctionalityMapJSON string `json:"functionality_map_json"`
	FindingsMD           string `json:"findings_md"`
	Assets               Assets `json:"assets"`
}

type ScanResult struct {
	Target      string         `json:"target"`
	Interrupted bool           `json:"interrupted"`
	Modules     []ModuleStatus `json:"modules"`
	Report      ReportResult   `json:"report"`
}

// NewServer builds the recon-mcp server: one `recon_<module>` tool per wired
// module, plus `recon_scan`, `recon_status` and `recon_report`.
func NewServer(version string) *sdk.Server {
	s := sdk.NewServer(&sdk.Implementation{Name: serverName, Version: version}, nil)

	for _, name := range pipeline.Names() {
		name := name
		sdk.AddTool(s, &sdk.Tool{
			Name:        "recon_" + name,
			Description: fmt.Sprintf("Run the recon module %q against the config target and return a summary (status, counter, produced files), not the raw content.", name),
		}, moduleHandler(name))
	}

	sdk.AddTool(s, &sdk.Tool{
		Name:        "recon_scan",
		Description: "Run the full recon pipeline (or the subset in `modules`) honoring dependencies, then write the report. Blocks until the scan finishes.",
	}, scanHandler)
	sdk.AddTool(s, &sdk.Tool{
		Name:        "recon_status",
		Description: "Recon state for the config target: whether a scan is running, the status of each module, asset counters. Runs nothing.",
	}, statusHandler)
	sdk.AddTool(s, &sdk.Tool{
		Name:        "recon_report",
		Description: "(Re)generate recon.json / functionality_map.json / findings.md from the current state, without re-running any module, and return their paths + counters.",
	}, reportHandler)

	return s
}

// loadConfig reloads the config and applies the domain override, like the
// CLI. Also returns the cleaned output_dir.
func loadConfig(path, domainOverride string) (*config.Config, string, error) {
	if path == "" {
		path = "recon.config.yaml"
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, "", err
	}
	if domainOverride != "" {
		cfg.Scope.Domain = domainOverride
	}
	return cfg, filepath.Clean(cfg.OutputDir), nil
}

func moduleHandler(name string) sdk.ToolHandlerFor[ModuleParams, ModuleResult] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, p ModuleParams) (*sdk.CallToolResult, ModuleResult, error) {
		cfg, outputDir, err := loadConfig(p.Config, p.Domain)
		if err != nil {
			return nil, ModuleResult{}, err
		}
		subs := p.SubsFile
		if subs == "" {
			subs = filepath.Join(outputDir, "subs_passive.txt")
		}
		in := modules.Input{
			Domain:    cfg.Scope.Domain,
			OrgName:   cfg.Scope.OrgName,
			SubsFile:  subs,
			OutputDir: outputDir,
		}

		st, err := state.Load(outputDir)
		if err != nil {
			return nil, ModuleResult{}, err
		}
		out, runErr := pipeline.RunOne(ctx, cfg, name, in, st)
		if err := st.Save(); err != nil {
			return nil, ModuleResult{}, fmt.Errorf("module ran but state could not be saved: %w", err)
		}

		res := ModuleResult{Module: name, Status: "done", Summary: out.Summary, Count: out.Count, Files: out.Files}
		if runErr != nil {
			// A module failure is a valid result (warn-and-continue), not a
			// protocol error: the client gets the status and the reason.
			res.Status = "failed"
			res.Summary = runErr.Error()
		}
		return nil, res, nil
	}
}

func scanHandler(ctx context.Context, _ *sdk.CallToolRequest, p ScanParams) (*sdk.CallToolResult, ScanResult, error) {
	cfg, outputDir, err := loadConfig(p.Config, p.Domain)
	if err != nil {
		return nil, ScanResult{}, err
	}
	selected := p.Modules
	if len(selected) == 0 {
		selected = pipeline.Names()
	}

	release, err := pipeline.AcquireLock(outputDir, selected)
	if err != nil {
		return nil, ScanResult{}, err
	}
	defer release()

	st, err := state.Load(outputDir)
	if err != nil {
		return nil, ScanResult{}, err
	}
	in := modules.Input{
		Domain:    cfg.Scope.Domain,
		OrgName:   cfg.Scope.OrgName,
		SubsFile:  filepath.Join(outputDir, "subs_passive.txt"),
		OutputDir: outputDir,
	}

	pipeline.Run(ctx, cfg, in, selected, st)

	report := writeReport(cfg, st)
	return nil, ScanResult{
		Target:      cfg.Scope.Domain,
		Interrupted: ctx.Err() != nil,
		Modules:     moduleStatuses(cfg, st),
		Report:      report,
	}, nil
}

func statusHandler(_ context.Context, _ *sdk.CallToolRequest, p ConfigParams) (*sdk.CallToolResult, StatusResult, error) {
	cfg, outputDir, err := loadConfig(p.Config, p.Domain)
	if err != nil {
		return nil, StatusResult{}, err
	}
	st, err := state.Load(outputDir)
	if err != nil {
		return nil, StatusResult{}, err
	}
	_, running := pipeline.Status(outputDir)
	rep, _ := target.Build(cfg, st)
	return nil, StatusResult{
		Target:      cfg.Scope.Domain,
		ScanRunning: running,
		Modules:     moduleStatuses(cfg, st),
		Assets:      toAssets(rep.Assets),
	}, nil
}

func reportHandler(_ context.Context, _ *sdk.CallToolRequest, p ConfigParams) (*sdk.CallToolResult, ReportResult, error) {
	cfg, outputDir, err := loadConfig(p.Config, p.Domain)
	if err != nil {
		return nil, ReportResult{}, err
	}
	st, err := state.Load(outputDir)
	if err != nil {
		return nil, ReportResult{}, err
	}
	return nil, writeReport(cfg, st), nil
}

// writeReport serializes the 3 files and returns the MCP ReportResult. On a
// write failure it still returns the counters (warn-and-continue): the paths
// stay filled, and the state is in state.json anyway.
func writeReport(cfg *config.Config, st *state.State) ReportResult {
	rep, _ := target.Build(cfg, st)
	res := ReportResult{Target: cfg.Scope.Domain, Assets: toAssets(rep.Assets)}
	if art, err := target.Write(cfg, st); err == nil {
		res.ReconJSON = art.Recon
		res.FunctionalityMapJSON = art.FunctionalityMap
		res.FindingsMD = art.Findings
	}
	return res
}

// moduleStatuses projects target's ReconReport into a list of ModuleStatus
// (roadmap order, including not-yet-run modules as "pending").
func moduleStatuses(cfg *config.Config, st *state.State) []ModuleStatus {
	rep, _ := target.Build(cfg, st)
	out := make([]ModuleStatus, 0, len(rep.Modules))
	for _, m := range rep.Modules {
		out = append(out, ModuleStatus{
			ID:      m.ID,
			Module:  m.Module,
			Status:  m.Status,
			Summary: m.Summary,
			Error:   m.Error,
		})
	}
	return out
}

func toAssets(a target.Assets) Assets {
	return Assets{
		Subdomains:         a.Subdomains,
		AliveHosts:         a.AliveHosts,
		URLs:               a.URLs,
		Vhosts:             a.Vhosts,
		OriginIPCandidates: a.OriginIPCandidates,
		TakeoverCandidates: a.TakeoverCandidates,
	}
}
