package state

import (
	"testing"
	"time"

	"github.com/Qtlas/BugBounty-recon/internal/modules"
)

func TestRecord_Statuses(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name       string
		runErr     error
		wantStatus Status
		wantErr    bool // Error set
		wantSumm   bool // Summary set
	}{
		{"success", nil, StatusDone, false, false},
		{"skip (ErrNoInput)", modules.NoInput("alive_subs.txt is empty or missing"), StatusSkipped, false, true},
		{"skip (bare sentinel)", modules.ErrNoInput, StatusSkipped, false, true},
		{"real failure", errToolCrashed{}, StatusFailed, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := &State{Entries: map[string]Entry{}}
			out := modules.Output{Summary: "ran"}
			st.Record("m", now, now, out, c.runErr)
			e := st.Entries["m"]
			if e.Status != c.wantStatus {
				t.Errorf("status = %q, want %q", e.Status, c.wantStatus)
			}
			if (e.Error != "") != c.wantErr {
				t.Errorf("Error=%q, wantErr=%v", e.Error, c.wantErr)
			}
			// A skip replaces the module Summary with its reason; a success
			// keeps the module Summary.
			if c.wantStatus == StatusSkipped && e.Summary == "" {
				t.Errorf("skip should carry the reason in Summary")
			}
			if c.wantStatus == StatusDone && e.Summary != "ran" {
				t.Errorf("done should keep module Summary, got %q", e.Summary)
			}
		})
	}
}

type errToolCrashed struct{}

func (errToolCrashed) Error() string { return "tool crashed: exit status 2" }
