// Package portscan implements port scanning and fingerprinting: naabu
// (open-port discovery) then nmap -sV -sC per IP in parallel (bounded by
// ThreadsFor) over the ports naabu found for that IP.
//
// Note: naabu's `-o` output is "ip:port", which `nmap -iL` cannot interpret
// (it expects a host list, not "host:port"). We therefore parse open_ports
// into map[ip][]port and run one targeted nmap per IP with the right `-p`.
package portscan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/runner"
)

const Name = "portscan"

type Module struct {
	cfg *config.Config
	run *runner.Runner
}

func New(cfg *config.Config, r *runner.Runner) *Module {
	return &Module{cfg: cfg, run: r}
}

func (m *Module) Name() string { return Name }

// DependsOn: consumes ips_asn.txt, the output of infra. Without it, there is
// nothing to scan.
func (m *Module) DependsOn() []string { return []string{"infra"} }

func (m *Module) Run(ctx context.Context, in modules.Input) (modules.Output, error) {
	ips := dedupSorted(readLines(filepath.Join(in.OutputDir, "ips_asn.txt")))
	if len(ips) == 0 {
		return modules.Output{}, modules.NoInput("portscan: no IPs found in ips_asn.txt (run infra first)")
	}

	uniqueIPsPath := filepath.Join(in.OutputDir, "unique_ips.txt")
	if err := writeLines(uniqueIPsPath, ips); err != nil {
		return modules.Output{}, fmt.Errorf("portscan: writing unique_ips.txt: %w", err)
	}

	openPortsPath := filepath.Join(in.OutputDir, "open_ports.txt")
	openPorts := m.runNaabu(ctx, uniqueIPsPath, openPortsPath, []string{"-exclude-ports", "80,443", "-rate", "2000"})

	var fullScanCount int
	if m.cfg.Modules.FullPorts {
		fullPath := filepath.Join(in.OutputDir, "ports_fullscan.txt")
		full := m.runNaabu(ctx, uniqueIPsPath, fullPath, []string{"-p", "-", "-exclude-ports", "80,443,8080,8000,8888"})
		fullScanCount = len(full)
	}

	byIP := groupByIP(openPorts)
	nmapPath := filepath.Join(in.OutputDir, "nmap_versions.txt")
	m.runNmap(ctx, byIP, nmapPath)

	files := map[string]string{
		"unique_ips":    uniqueIPsPath,
		"open_ports":    openPortsPath,
		"nmap_versions": nmapPath,
	}
	summary := fmt.Sprintf("%d open ports across %d IPs", len(openPorts), len(byIP))
	if m.cfg.Modules.FullPorts {
		files["ports_fullscan"] = filepath.Join(in.OutputDir, "ports_fullscan.txt")
		summary += fmt.Sprintf(", %d ports found in full scan", fullScanCount)
	}

	return modules.Output{Files: files, Summary: summary, Count: len(openPorts)}, nil
}

// runNaabu writes its output via -o, then we re-read it to return it as
// "ip:port" lines usable by the rest of the module.
func (m *Module) runNaabu(ctx context.Context, ipsPath, outPath string, extraArgs []string) []string {
	args := append([]string{"-l", ipsPath, "-o", outPath}, extraArgs...)
	if _, err := m.run.Run(ctx, "naabu", args, nil); err != nil {
		warn("naabu failed (continuing): %v", err)
	}
	return readLines(outPath)
}

func groupByIP(openPorts []string) map[string][]string {
	byIP := make(map[string][]string)
	for _, line := range openPorts {
		ip, port, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if _, err := strconv.Atoi(port); err != nil {
			continue
		}
		byIP[ip] = append(byIP[ip], port)
	}
	return byIP
}

// runNmap runs one `nmap -sV -sC -p {ports} {ip}` per IP, in parallel
// (bounded by ThreadsFor), and concatenates the outputs into a single file.
func (m *Module) runNmap(ctx context.Context, byIP map[string][]string, outPath string) {
	if len(byIP) == 0 {
		writeLines(outPath, nil)
		return
	}
	threads := m.cfg.ThreadsFor(Name)
	if threads <= 0 {
		threads = 10
	}
	sem := make(chan struct{}, threads)

	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	outputs := make([]string, len(ips))
	var g errgroup.Group
	for i, ip := range ips {
		i, ip := i, ip
		g.Go(func() error {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return nil
			}
			defer func() { <-sem }()

			ports := strings.Join(byIP[ip], ",")
			args := []string{"-sV", "-sC", "-p", ports, ip}
			result, err := m.run.Run(ctx, "nmap", args, nil)
			if err != nil {
				warn("nmap on %s failed (continuing): %v", ip, err)
				return nil
			}
			outputs[i] = result.Stdout
			return nil
		})
	}
	g.Wait()

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		warn("creating output dir (continuing): %v", err)
		return
	}
	f, err := os.Create(outPath)
	if err != nil {
		warn("writing nmap_versions.txt (continuing): %v", err)
		return
	}
	defer f.Close()
	for _, out := range outputs {
		f.WriteString(out)
		f.WriteString("\n")
	}
}

func dedupSorted(lines []string) []string {
	set := make(map[string]struct{}, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			set[l] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

func readLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
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
	fmt.Fprintf(os.Stderr, "portscan: "+format+"\n", args...)
}
