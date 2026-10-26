package alive

import (
	"encoding/json"
	"strings"
	"testing"
)

// A representative line of `httpx -json`, trimmed to the fields we read.
const realHTTPXLine = `{"url":"https://www.example.com","input":"www.example.com","title":"Example","webserver":"cloudflare","status_code":200,"cdn_name":"cloudflare","cdn_type":"waf","cdn":true,"a":["104.18.144.198","104.17.79.196"],"aaaa":["2606:4700::6811:4fc4"],"tech":["Cloudflare","Next.js","hCaptcha"]}`

func TestParseWhatweb_KeepsRichestLinePerHost(t *testing.T) {
	// whatweb emits several lines per host; we must keep the richest one
	// (the 200 with WordPress), not a 301 redirect.
	lines := []string{
		`http://www.example.com [301 Moved Permanently] HTTPServer[cloudflare], RedirectLocation[https://www.example.com/]`,
		`https://www.example.com [200 OK] HTML5, HTTPServer[cloudflare], Title[Example], WordPress, X-Frame-Options[SAMEORIGIN]`,
		`http://api.example.com [301 Moved Permanently] HTTPServer[cloudflare]`,
		``,
	}
	got := parseWhatweb(lines)
	if len(got) != 2 {
		t.Fatalf("got %d hosts, want 2: %v", len(got), got)
	}
	if !strings.Contains(got["www.example.com"], "WordPress") || !strings.Contains(got["www.example.com"], "200 OK") {
		t.Errorf("www: kept line = %q (should be the 200 with WordPress)", got["www.example.com"])
	}
	if !strings.Contains(got["api.example.com"], "301") {
		t.Errorf("api: %q", got["api.example.com"])
	}
}

func TestHTTPXRecord_ParsesCDNAndIPs(t *testing.T) {
	var rec httpxRecord
	if err := json.Unmarshal([]byte(realHTTPXLine), &rec); err != nil {
		t.Fatalf("unmarshal httpx line: %v", err)
	}
	if rec.Input != "www.example.com" || rec.StatusCode != 200 || rec.Webserver != "cloudflare" {
		t.Errorf("base fields misread: %+v", rec)
	}
	if !rec.CDN || rec.CDNName != "cloudflare" || rec.CDNType != "waf" {
		t.Errorf("CDN misread: cdn=%v name=%q type=%q", rec.CDN, rec.CDNName, rec.CDNType)
	}
	if len(rec.A) != 2 || len(rec.AAAA) != 1 {
		t.Errorf("IPs misread: a=%v aaaa=%v", rec.A, rec.AAAA)
	}
	if len(rec.Tech) != 3 {
		t.Errorf("tech misread: %v", rec.Tech)
	}
}

// Representative output of `webanalyze -output json`: a banner first, then one
// JSON object per line (JSONL), NOT a global array.
const realWebanalyze = ` :: webanalyze        : v0.3.9
 :: workers           : 4
 :: technologies      : technologies.json

{"hostname":"http://api.example.com","matches":[{"app":{"cats":["16"]},"app_name":"HSTS","version":""},{"app":{"cats":["31"]},"app_name":"Cloudflare","version":""},{"app_name":"HTTP/3"}]}
{"hostname":"http://www.example.com","matches":[{"app_name":"Amazon S3"},{"app_name":"hCaptcha"}]}`

func TestParseWebanalyze(t *testing.T) {
	recs := parseWebanalyze(realWebanalyze)
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2 (the banner must not be parsed)", len(recs))
	}
	if recs[0].Hostname != "http://api.example.com" {
		t.Errorf("hostname = %q", recs[0].Hostname)
	}
	// The readable field is app_name (not app), and hostOf must normalize.
	if host := hostOf(recs[0].Hostname); host != "api.example.com" {
		t.Errorf("hostOf = %q, want api.example.com", host)
	}
	var names []string
	for _, m := range recs[0].Matches {
		names = append(names, m.AppName)
	}
	want := []string{"HSTS", "Cloudflare", "HTTP/3"}
	if len(names) != len(want) {
		t.Fatalf("app_names = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("app_name[%d] = %q, want %q", i, names[i], want[i])
		}
	}
}

func TestIsPythonHTTPX(t *testing.T) {
	// Signature of the Python httpx library's CLI (click) served instead of
	// ProjectDiscovery's httpx.
	pythonErr := "Usage: httpx [OPTIONS] URL\n\nError: No such option '-s'."
	if !isPythonHTTPX(pythonErr) {
		t.Error("should detect the Python httpx CLI signature")
	}

	// A genuine PD httpx error (or any other failure) must not match.
	for _, s := range []string{
		"",
		"connection refused",
		"httpx: context canceled",
		"[ERR] could not resolve host",
	} {
		if isPythonHTTPX(s) {
			t.Errorf("false positive on %q", s)
		}
	}
}
