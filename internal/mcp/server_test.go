package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Qtlas/BugBounty-recon/internal/pipeline"
)

// connect wires a recon-mcp server and a client over an in-memory transport
// and returns the client session. NewServer panics if a tool input/output
// schema cannot be inferred, so this test also covers the validity of all
// schemas.
func connect(t *testing.T) *sdk.ClientSession {
	t.Helper()
	srv := NewServer("test")
	clientT, serverT := sdk.NewInMemoryTransports()

	ctx := context.Background()
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "test-client", Version: "test"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func TestListTools(t *testing.T) {
	cs := connect(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}
	// One tool per wired module + scan/status/report.
	wantCount := len(pipeline.Names()) + 3
	if len(res.Tools) != wantCount {
		t.Errorf("got %d tools, want %d", len(res.Tools), wantCount)
	}
	for _, name := range []string{"recon_passive", "recon_infra", "recon_osintdork", "recon_scan", "recon_status", "recon_report"} {
		if !got[name] {
			t.Errorf("missing tool %q", name)
		}
	}
}

// writeConfig writes a minimal config pointing at a temporary output_dir.
func writeConfig(t *testing.T) (cfgPath, outDir string) {
	t.Helper()
	outDir = t.TempDir()
	cfgPath = filepath.Join(t.TempDir(), "recon.config.yaml")
	body := "scope:\n  domain: demo.example\n  org_name: Demo\noutput_dir: " + outDir + "\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfgPath, outDir
}

func TestStatusTool_NoRunYet(t *testing.T) {
	cs := connect(t)
	cfgPath, _ := writeConfig(t)

	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      "recon_status",
		Arguments: map[string]any{"config": cfgPath},
	})
	if err != nil {
		t.Fatalf("CallTool status: %v", err)
	}
	if res.IsError {
		t.Fatalf("status returned error result: %+v", res.Content)
	}

	var out StatusResult
	remarshal(t, res.StructuredContent, &out)
	if out.Target != "demo.example" {
		t.Errorf("target = %q, want demo.example", out.Target)
	}
	if out.ScanRunning {
		t.Errorf("scan should not be running")
	}
	if len(out.Modules) != len(pipeline.Names()) {
		t.Errorf("got %d module statuses, want %d", len(out.Modules), len(pipeline.Names()))
	}
	for _, m := range out.Modules {
		if m.Status != "pending" {
			t.Errorf("module %s status = %q, want pending (nothing ran)", m.Module, m.Status)
		}
	}
}

func TestReportTool_WritesFiles(t *testing.T) {
	cs := connect(t)
	cfgPath, outDir := writeConfig(t)

	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      "recon_report",
		Arguments: map[string]any{"config": cfgPath},
	})
	if err != nil {
		t.Fatalf("CallTool report: %v", err)
	}
	if res.IsError {
		t.Fatalf("report returned error result: %+v", res.Content)
	}
	var out ReportResult
	remarshal(t, res.StructuredContent, &out)

	for _, p := range []string{out.ReconJSON, out.FunctionalityMapJSON, out.FindingsMD} {
		if p == "" {
			t.Fatalf("report path empty in %+v", out)
		}
		if _, err := os.Stat(p); err != nil {
			t.Errorf("report file not written: %s (%v)", p, err)
		}
	}
	if filepath.Dir(out.ReconJSON) != outDir {
		t.Errorf("recon.json written to %s, want under %s", out.ReconJSON, outDir)
	}
}

func TestModuleTool_BadConfigIsError(t *testing.T) {
	cs := connect(t)
	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      "recon_passive",
		Arguments: map[string]any{"config": "/nonexistent/recon.config.yaml"},
	})
	// A missing config is a tool-level error (IsError result), not a transport
	// error.
	if err != nil {
		t.Fatalf("transport error (expected tool-level error instead): %v", err)
	}
	if !res.IsError {
		t.Errorf("expected IsError for missing config, got %+v", res)
	}
}

// remarshal converts the StructuredContent (decoded as any/map) back into a
// typed struct, via a JSON round-trip.
func remarshal(t *testing.T, v any, dst any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatalf("unmarshal into %T: %v", dst, err)
	}
}
