package originip

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCdnFrontedHosts(t *testing.T) {
	dir := t.TempDir()
	// Shape of tech_stack.json (array of techInfo, field cdn).
	body := `[
	  {"host":"www.example.com","cdn":true,"cdn_name":"cloudflare"},
	  {"host":"API.example.com","cdn":true},
	  {"host":"direct.example.com","cdn":false},
	  {"host":"nocdn.example.com"}
	]`
	if err := os.WriteFile(filepath.Join(dir, "tech_stack.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	set, ok := cdnFrontedHosts(dir)
	if !ok {
		t.Fatal("ok=false although the file is valid")
	}
	if len(set) != 2 {
		t.Fatalf("got %d CDN hosts, want 2: %v", len(set), set)
	}
	if !set["www.example.com"] {
		t.Error("www.example.com should be CDN")
	}
	if !set["api.example.com"] { // normalized to lowercase
		t.Error("API.example.com should match in lowercase")
	}
	if set["direct.example.com"] || set["nocdn.example.com"] {
		t.Error("hosts without cdn:true must not be in the set")
	}
}

func TestCdnFrontedHosts_MissingOrInvalid(t *testing.T) {
	dir := t.TempDir()
	if _, ok := cdnFrontedHosts(dir); ok {
		t.Error("missing file -> ok must be false (fallback)")
	}
	if err := os.WriteFile(filepath.Join(dir, "tech_stack.json"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := cdnFrontedHosts(dir); ok {
		t.Error("invalid JSON -> ok must be false (fallback)")
	}
}
