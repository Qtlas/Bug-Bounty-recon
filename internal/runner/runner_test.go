package runner

import "testing"

func TestFirstInstalled(t *testing.T) {
	// "sh" is present on any POSIX system; the first name is not.
	got, ok := FirstInstalled("definitely-not-a-real-binary-xyz", "sh")
	if !ok || got != "sh" {
		t.Errorf("FirstInstalled(...) = %q,%v ; want sh,true", got, ok)
	}

	if _, ok := FirstInstalled("definitely-not-a-real-binary-xyz", "also-not-real-abc"); ok {
		t.Error("FirstInstalled should return false when no candidate is on PATH")
	}

	if _, ok := FirstInstalled(); ok {
		t.Error("FirstInstalled() with no names should return false")
	}
}
