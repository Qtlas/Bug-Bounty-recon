// Package infra implements infrastructure mapping. Independent of the
// subdomain-enumeration branch (it needs only domain/org_name): asnmap +
// mapcidr + dnsx -ptr to map the target's full ASN, metabigor as a complement
// if org_name is set, plus TLD expansion (direct HTTP probe, no external
// binary required for that part).
package infra

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Qtlas/BugBounty-recon/internal/config"
	"github.com/Qtlas/BugBounty-recon/internal/modules"
	"github.com/Qtlas/BugBounty-recon/internal/runner"
)

const Name = "infra"

// commonTLDs is a deliberately small list of the TLDs most relevant to this
// kind of recon: not the full IANA list (~1500 entries, high network cost for
// little gain). Large organizations that neglect an extension usually do so
// on a commercial or generic TLD close to their name, not an obscure ccTLD.
var commonTLDs = []string{
	"com", "net", "org", "io", "co", "dev", "app", "xyz", "info", "biz",
	"cloud", "tech", "online", "site", "store", "shop", "top", "club",
	"live", "world", "digital", "network", "systems", "solutions", "group",
	"global", "agency", "studio", "media", "id",
	"uk", "de", "fr", "nl", "eu", "us", "ca", "au", "in", "ru", "cn", "jp",
	"br", "es", "it", "pl", "se", "no", "dk", "fi", "ch", "at", "be", "pt",
	"gr", "ie", "nz", "sg", "hk", "tw", "kr",
}

var (
	asnRe  = regexp.MustCompile(`(?i)\bAS\d+\b`)
	cidrRe = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b`)
)

type Module struct {
	cfg *config.Config
	run *runner.Runner
}

func New(cfg *config.Config, r *runner.Runner) *Module {
	return &Module{cfg: cfg, run: r}
}

func (m *Module) Name() string { return Name }

// DependsOn returns nil: infra maps the ASN/org from domain/org_name
// directly, in parallel with the subdomain-enumeration branch.
func (m *Module) DependsOn() []string { return nil }

func (m *Module) Run(ctx context.Context, in modules.Input) (modules.Output, error) {
	if in.Domain == "" {
		return modules.Output{}, fmt.Errorf("infra: domain is required")
	}
	if err := os.MkdirAll(in.OutputDir, 0o755); err != nil {
		return modules.Output{}, fmt.Errorf("infra: creating output dir: %w", err)
	}

	// ASN/CIDR discovery and TLD expansion are independent of each other, run
	// in parallel (intra-module concurrency).
	var asns, cidrs map[string]struct{}
	var tldLines []string
	var g errgroup.Group
	g.Go(func() error {
		asns, cidrs = m.discoverASN(ctx, in.Domain, in.OrgName)
		return nil
	})
	g.Go(func() error {
		tldLines = m.expandTLDs(ctx, in.Domain)
		return nil
	})
	g.Wait()

	asnPath := filepath.Join(in.OutputDir, "asn.txt")
	cidrPath := filepath.Join(in.OutputDir, "cidr_ranges.txt")
	ipsPath := filepath.Join(in.OutputDir, "ips_asn.txt")
	ptrPath := filepath.Join(in.OutputDir, "ptr_domains.txt")
	tldPath := filepath.Join(in.OutputDir, "tlds_alive.txt")

	if err := writeLines(asnPath, sortedKeys(asns)); err != nil {
		return modules.Output{}, fmt.Errorf("infra: writing asn.txt: %w", err)
	}
	cidrList := sortedKeys(cidrs)
	if err := writeLines(cidrPath, cidrList); err != nil {
		return modules.Output{}, fmt.Errorf("infra: writing cidr_ranges.txt: %w", err)
	}
	if err := writeLines(tldPath, tldLines); err != nil {
		return modules.Output{}, fmt.Errorf("infra: writing tlds_alive.txt: %w", err)
	}

	// mapcidr (IP expansion) and dnsx -ptr both consume cidr_ranges, but
	// dnsx -ptr does not need to wait for mapcidr's output, so they run in
	// parallel too.
	var ips []string
	var ptrLines []string
	if len(cidrList) > 0 {
		g = errgroup.Group{}
		g.Go(func() error {
			ips = m.expandCIDRs(ctx, cidrList)
			return nil
		})
		g.Go(func() error {
			ptrLines = m.resolvePTR(ctx, cidrList)
			return nil
		})
		g.Wait()
	}
	if in.OrgName != "" {
		ips = append(ips, m.metabigorOrgIPs(ctx, in.OrgName)...)
	}
	ips = dedupSorted(ips)

	if err := writeLines(ipsPath, ips); err != nil {
		return modules.Output{}, fmt.Errorf("infra: writing ips_asn.txt: %w", err)
	}
	if err := writeLines(ptrPath, ptrLines); err != nil {
		return modules.Output{}, fmt.Errorf("infra: writing ptr_domains.txt: %w", err)
	}

	return modules.Output{
		Files: map[string]string{
			"asn":         asnPath,
			"cidr_ranges": cidrPath,
			"ips_asn":     ipsPath,
			"ptr_domains": ptrPath,
			"tlds_alive":  tldPath,
		},
		Summary: fmt.Sprintf("%d ASN, %d CIDR ranges, %d IPs, %d PTR records, %d alive TLD variants",
			len(asns), len(cidrList), len(ips), len(ptrLines), len(tldLines)),
		Count: len(ips),
	}, nil
}

// discoverASN runs `asnmap -d domain -silent`, which returns either ASN
// numbers or CIDRs directly depending on the target. Both forms are detected
// by regex; for each ASN found, `asnmap -a {asn} -silent` fills in its CIDRs,
// in parallel.
func (m *Module) discoverASN(ctx context.Context, domain, orgName string) (asns, cidrs map[string]struct{}) {
	asns = make(map[string]struct{})
	cidrs = make(map[string]struct{})
	var mu sync.Mutex

	collect := func(output string) {
		mu.Lock()
		defer mu.Unlock()
		for _, m := range asnRe.FindAllString(output, -1) {
			asns[strings.ToUpper(m)] = struct{}{}
		}
		for _, m := range cidrRe.FindAllString(output, -1) {
			cidrs[m] = struct{}{}
		}
	}

	env := m.pdcpEnv()

	if result, err := m.run.RunWithEnv(ctx, "asnmap", []string{"-d", domain, "-silent"}, env, nil); err != nil {
		warn("asnmap -d failed (continuing): %v", err)
	} else {
		collect(result.Stdout)
	}
	if orgName != "" {
		if result, err := m.run.RunWithEnv(ctx, "asnmap", []string{"-org", orgName, "-silent"}, env, nil); err != nil {
			warn("asnmap -org failed (continuing): %v", err)
		} else {
			collect(result.Stdout)
		}
	}

	mu.Lock()
	asnList := sortedKeys(asns)
	mu.Unlock()

	var g errgroup.Group
	for _, asn := range asnList {
		asn := strings.TrimPrefix(asn, "AS")
		g.Go(func() error {
			result, err := m.run.RunWithEnv(ctx, "asnmap", []string{"-a", asn, "-silent"}, env, nil)
			if err != nil {
				warn("asnmap -a %s failed (continuing): %v", asn, err)
				return nil
			}
			collect(result.Stdout)
			return nil
		})
	}
	g.Wait()

	return asns, cidrs
}

// pdcpEnv returns the PDCP_API_KEY environment variable if
// api_keys.pdcp_api_key is set, nil otherwise. asnmap refuses to run without
// ProjectDiscovery Cloud authentication; without a key provided here, the
// alternative is `asnmap -auth` once outside this tool, which persists the
// key in asnmap's own config.
func (m *Module) pdcpEnv() []string {
	if m.cfg.APIKeys.PDCPAPIKey == "" {
		return nil
	}
	return []string{"PDCP_API_KEY=" + m.cfg.APIKeys.PDCPAPIKey}
}

// metabigorEnv works around a panic at metabigor startup: its dependency
// go4.org/unsafe/assume-no-moving-gc panics if the Go toolchain used to
// compile it (via `go install`) is newer than the versions it recognizes as
// safe, unless explicitly given the go-ahead for that version — exactly what
// the panic message itself suggests. Go's GC has not become moving; only the
// library's allow-list is behind.
func metabigorEnv() []string {
	return []string{"ASSUME_NO_MOVING_GC_UNSAFE_RISK_IT_WITH=" + goMajorMinor()}
}

// goMajorMinor returns "go1.26" from runtime.Version() (e.g. "go1.26.0"), the
// format ASSUME_NO_MOVING_GC_UNSAFE_RISK_IT_WITH expects.
func goMajorMinor() string {
	v := strings.TrimPrefix(runtime.Version(), "go")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return runtime.Version()
	}
	return "go" + parts[0] + "." + parts[1]
}

// expandCIDRs pipes all found CIDRs at once into `mapcidr -silent` (mapcidr
// reads each line of stdin, so a single grouped call produces the same result
// without re-running the binary N times).
func (m *Module) expandCIDRs(ctx context.Context, cidrs []string) []string {
	result, err := m.run.RunWithInput(ctx, "mapcidr", []string{"-silent"}, strings.Join(cidrs, "\n"), nil)
	if err != nil {
		warn("mapcidr failed (continuing): %v", err)
		return nil
	}
	return linesOf(result.Stdout)
}

// resolvePTR pipes the CIDRs into `dnsx -silent -resp-only -ptr`, after
// dropping ranges that are too large (m.ptrMaxHostBits), with a dedicated
// deadline (m.ptrTimeout) and output streamed live (otherwise infra stays a
// silent "RUN" during the whole sweep). All three bounds are overridable per
// target via rate_limits.per_module.infra.
func (m *Module) resolvePTR(ctx context.Context, cidrs []string) []string {
	maxBits := m.ptrMaxHostBits()
	targets := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		if ptrTooLarge(c, maxBits) {
			warn("dnsx -ptr: skipping %s (host part > %d bits, reverse DNS too costly)", c, maxBits)
			continue
		}
		targets = append(targets, c)
	}
	if len(targets) == 0 {
		return nil
	}

	timeout := m.ptrTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	onLine := func(line string) { fmt.Fprintf(os.Stderr, "infra: dnsx-ptr: %s\n", line) }
	args := []string{"-silent", "-resp-only", "-ptr", "-t", fmt.Sprintf("%d", m.cfg.ThreadsFor(Name))}
	result, err := m.run.RunWithInput(ctx, "dnsx", args, strings.Join(targets, "\n"), onLine)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			warn("dnsx -ptr exceeded its dedicated %s budget (partial results kept, continuing)", timeout)
		} else {
			warn("dnsx -ptr failed (continuing): %v", err)
		}
	}
	if result == nil {
		return nil
	}
	return linesOf(result.Stdout) // partial kept on timeout
}

// ptrTooLarge reports whether a CIDR holds too many IPs for a reasonable
// reverse DNS (host part > maxHostBits). A non-CIDR entry (a bare IP) is let
// through: dnsx handles it directly.
func ptrTooLarge(cidr string, maxHostBits int) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ones, bits := ipnet.Mask.Size()
	return bits-ones > maxHostBits
}

// gcVersionRe extracts the go1.NN version that the
// go4.org/unsafe/assume-no-moving-gc panic asks for in its own message
// (`... ASSUME_NO_MOVING_GC_UNSAFE_RISK_IT_WITH=go1.NN set.`).
var gcVersionRe = regexp.MustCompile(`ASSUME_NO_MOVING_GC_UNSAFE_RISK_IT_WITH=(go1\.\d+)`)

// defaultMetabigorTimeout bounds metabigor independently of the module's
// global budget. `metabigor net --org` scrapes external sources with no
// internal timeout: without this dedicated deadline, a slow source would hold
// up the whole infra -> merge -> alive branch. Since metabigor is only a
// complement to asnmap (warn-and-continue), we prefer to abandon it after a
// few minutes rather than hold back the DAG. Overridable per target via
// rate_limits.per_module.infra.metabigor_timeout_minutes.
const defaultMetabigorTimeout = 4 * time.Minute

// Default bounds for dnsx -ptr, overridable per target via
// rate_limits.per_module.infra (see config.ModuleRateLimit).
const (
	defaultPTRTimeout     = 10 * time.Minute
	defaultPTRMaxHostBits = 16 // /16 IPv4 = 65536 IPs
)

// limits returns the per_module.infra override (zero-value if absent: reading
// a nil map is safe in Go).
func (m *Module) limits() config.ModuleRateLimit { return m.cfg.RateLimits.PerModule[Name] }

func (m *Module) metabigorTimeout() time.Duration {
	if n := m.limits().MetabigorTimeoutMinutes; n > 0 {
		return time.Duration(n) * time.Minute
	}
	return defaultMetabigorTimeout
}

func (m *Module) ptrTimeout() time.Duration {
	if n := m.limits().PTRTimeoutMinutes; n > 0 {
		return time.Duration(n) * time.Minute
	}
	return defaultPTRTimeout
}

func (m *Module) ptrMaxHostBits() int {
	if n := m.limits().PTRMaxHostBits; n > 0 {
		return n
	}
	return defaultPTRMaxHostBits
}

// runMetabigor runs metabigor with the assume-no-moving-gc guard. Subtlety:
// that guard compares the environment variable to the Go version *metabigor
// itself* was built with (via `go install`), not this tool's. When they
// differ (metabigor installed with an older toolchain than the one that built
// this tool), the value derived from runtime.Version() does not match and
// metabigor panics anyway. We then read the exact version the panic message
// asks for and retry once with it — self-correcting whatever metabigor's
// toolchain is.
func (m *Module) runMetabigor(ctx context.Context, args []string, stdin string) (*runner.Result, error) {
	// Dedicated deadline (see defaultMetabigorTimeout); combines with the
	// runner timeout (shortest wins) and with a quit.
	timeout := m.metabigorTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Stream the output live: metabigor prints nothing otherwise and infra
	// stays a silent "RUN"; this shows it is working (and what it finds).
	onLine := func(line string) { fmt.Fprintf(os.Stderr, "infra: metabigor: %s\n", line) }

	result, err := m.run.RunWithInputEnv(ctx, "metabigor", args, stdin, metabigorEnv(), onLine)
	if err != nil && result != nil {
		if sub := gcVersionRe.FindStringSubmatch(result.Stderr); sub != nil && sub[1] != goMajorMinor() {
			env := []string{"ASSUME_NO_MOVING_GC_UNSAFE_RISK_IT_WITH=" + sub[1]}
			result, err = m.run.RunWithInputEnv(ctx, "metabigor", args, stdin, env, onLine)
		}
	}
	// Our dedicated deadline fired: give a precise message (the runner would
	// otherwise report its own 30-min timeout, misleading here).
	if ctx.Err() == context.DeadlineExceeded {
		return result, fmt.Errorf("metabigor exceeded its dedicated %s budget (complement to asnmap, abandoned)", timeout)
	}
	return result, err
}

// metabigorOrgIPs pipes org_name into `metabigor net --org`, complementing
// asnmap with IPs registered to the organization via other sources.
func (m *Module) metabigorOrgIPs(ctx context.Context, orgName string) []string {
	result, err := m.runMetabigor(ctx, []string{"net", "--org"}, orgName)
	if err != nil {
		warn("metabigor failed (continuing): %v", err)
		return nil
	}
	var ips []string
	for _, line := range linesOf(result.Stdout) {
		if cidrRe.MatchString(line) {
			ips = append(ips, cidrRe.FindAllString(line, -1)...)
		}
	}
	return ips
}

// expandTLDs tests, for the base name extracted from `domain`, each TLD in
// commonTLDs other than the one already used, in parallel (pool bounded by
// ThreadsFor). No external binary: a direct HTTP request.
func (m *Module) expandTLDs(ctx context.Context, domain string) []string {
	base, currentTLD := splitBaseTLD(domain)
	if base == "" {
		return nil
	}

	threads := m.cfg.ThreadsFor(Name)
	if threads <= 0 {
		threads = 20
	}
	sem := make(chan struct{}, threads)
	client := &http.Client{Timeout: 8 * time.Second}

	var mu sync.Mutex
	var alive []string
	var g errgroup.Group
	for _, tld := range commonTLDs {
		if tld == currentTLD {
			continue
		}
		tld := tld
		g.Go(func() error {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return nil
			}
			defer func() { <-sem }()

			candidate := base + "." + tld
			if status, ok := probeAlive(ctx, client, candidate); ok {
				mu.Lock()
				alive = append(alive, fmt.Sprintf("%s [%d]", candidate, status))
				mu.Unlock()
			}
			return nil
		})
	}
	g.Wait()

	sort.Strings(alive)
	return alive
}

func probeAlive(ctx context.Context, client *http.Client, host string) (int, bool) {
	for _, scheme := range []string{"https://", "http://"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+host, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode > 0 && resp.StatusCode < 500 {
			return resp.StatusCode, true
		}
	}
	return 0, false
}

// splitBaseTLD extracts a plausible base name for expansion (e.g.
// "target.com" -> "target", "com"). Deliberately simple heuristic: it does
// not handle compound TLDs (co.uk) correctly, acceptable for a cheap default
// module.
func splitBaseTLD(domain string) (base, tld string) {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", ""
	}
	return strings.Join(parts[:len(parts)-1], "."), parts[len(parts)-1]
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func linesOf(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func dedupSorted(lines []string) []string {
	set := make(map[string]struct{}, len(lines))
	for _, l := range lines {
		set[l] = struct{}{}
	}
	return sortedKeys(set)
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
	fmt.Fprintf(os.Stderr, "infra: "+format+"\n", args...)
}
