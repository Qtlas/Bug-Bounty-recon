package infra

import (
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// A real panic message (metabigor built with go1.26, this tool with go1.27),
// trimmed to the essential.
const realPanic = `panic: Something in this program imports go4.org/unsafe/assume-no-moving-gc to declare that it assumes a non-moving garbage collector, but your version of go4.org/unsafe/assume-no-moving-gc hasn't been updated to assert that it's safe against the go1.26 runtime. If you want to risk it, run with environment variable ASSUME_NO_MOVING_GC_UNSAFE_RISK_IT_WITH=go1.26 set.`

func TestGCVersionRe_ExtractsRequestedVersion(t *testing.T) {
	sub := gcVersionRe.FindStringSubmatch(realPanic)
	if sub == nil {
		t.Fatal("regex did not match the real panic message")
	}
	if sub[1] != "go1.26" {
		t.Errorf("extracted %q, want go1.26", sub[1])
	}
}

func TestGCVersionRe_NoMatchOnUnrelatedError(t *testing.T) {
	if gcVersionRe.MatchString("exit status 1 (stderr: some other failure)") {
		t.Error("regex matched an unrelated error")
	}
}

func TestPtrTooLarge(t *testing.T) {
	cases := []struct {
		cidr string
		want bool
	}{
		{"203.0.113.0/24", false},  // 256 IPs, OK
		{"198.51.100.0/22", false}, // 1024 IPs, OK
		{"192.0.0.0/16", false},    // 65536 IPs, exactly the limit, OK
		{"10.0.0.0/15", true},      // 131072 IPs, too large
		{"10.0.0.0/8", true},       // huge
		{"2001:db8::/112", false},  // 65536 IPv6, OK
		{"2001:db8::/32", true},    // astronomical
		{"203.0.113.5", false},     // bare IP (not a CIDR): let through
		{"garbage", false},         // unparsable: let through
	}
	for _, c := range cases {
		if got := ptrTooLarge(c.cidr, defaultPTRMaxHostBits); got != c.want {
			t.Errorf("ptrTooLarge(%q) = %v, want %v", c.cidr, got, c.want)
		}
	}
}

func TestGoMajorMinor(t *testing.T) {
	got := goMajorMinor()
	if !strings.HasPrefix(got, "go1.") {
		t.Errorf("goMajorMinor() = %q, want go1.x form", got)
	}
	// Must be strictly major.minor (two segments), not the patch.
	if regexp.MustCompile(`^go\d+\.\d+$`).MatchString(got) == false {
		t.Errorf("goMajorMinor() = %q, want exactly goMAJOR.MINOR (got runtime %q)", got, runtime.Version())
	}
}
