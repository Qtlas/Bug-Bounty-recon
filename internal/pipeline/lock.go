package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const lockFileName = "scan.lock"

// LockInfo describes the active scan for a target: which process (pid),
// started when, with which modules. Persisted as JSON in
// <output_dir>/scan.lock while a scan runs, so that quit/status launched from
// another terminal can find it.
type LockInfo struct {
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	Modules   []string  `json:"modules"`
}

func lockPath(outputDir string) string { return filepath.Join(outputDir, lockFileName) }

// AcquireLock creates the lock file for outputDir, and fails if a scan is
// already running for this target (a live process behind an existing lock).
// The caller must call release() once the scan is done (defer).
func AcquireLock(outputDir string, mods []string) (release func(), err error) {
	if info, running := Status(outputDir); running {
		return nil, fmt.Errorf("a scan is already running for this target (pid %d, started %s) — use `recon-cli quit` to stop it first",
			info.PID, info.StartedAt.Format(time.RFC3339))
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, err
	}
	info := LockInfo{PID: os.Getpid(), StartedAt: time.Now(), Modules: mods}
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return nil, err
	}
	path := lockPath(outputDir)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, err
	}
	return func() { os.Remove(path) }, nil
}

func readLock(outputDir string) (LockInfo, error) {
	var info LockInfo
	data, err := os.ReadFile(lockPath(outputDir))
	if err != nil {
		return info, err
	}
	err = json.Unmarshal(data, &info)
	return info, err
}

// processAlive checks that a pid maps to a live process without sending it a
// real signal (signal 0 = presence test only, POSIX).
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// Status returns the lock info for outputDir and whether the process holding
// it is still alive (an orphan lock, e.g. after a kill -9, yields
// running=false).
func Status(outputDir string) (info LockInfo, running bool) {
	info, err := readLock(outputDir)
	if err != nil {
		return LockInfo{}, false
	}
	return info, processAlive(info.PID)
}

// Quit sends SIGTERM to the process holding the lock for outputDir: the
// running scan cancels its context, lets in-flight external commands be
// killed cleanly, marks remaining modules "interrupted", and exits.
func Quit(outputDir string) error {
	info, running := Status(outputDir)
	if !running {
		return fmt.Errorf("no scan currently running for this target")
	}
	proc, err := os.FindProcess(info.PID)
	if err != nil {
		return err
	}
	return proc.Signal(syscall.SIGTERM)
}
