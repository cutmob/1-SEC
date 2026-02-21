package main

import "testing"

func TestIsNewer(t *testing.T) {
	tests := []struct {
		latest, current string
		want            bool
	}{
		{"0.3.7", "0.3.6", true},
		{"0.4.0", "0.3.6", true},
		{"1.0.0", "0.9.9", true},
		{"0.3.6", "0.3.6", false},
		{"0.3.5", "0.3.6", false},
		{"0.2.9", "0.3.0", false},
		{"v1.0.0", "0.3.6", true},
		{"0.3.7", "v0.3.6", true},
	}
	for _, tt := range tests {
		got := isNewer(tt.latest, tt.current)
		if got != tt.want {
			t.Errorf("isNewer(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
		}
	}
}

func TestHasFlag(t *testing.T) {
	args := []string{"up", "--quiet", "--config", "foo.yaml"}
	if !hasFlag(args, "-q", "--quiet") {
		t.Error("expected hasFlag to find --quiet")
	}
	if hasFlag(args, "-v", "--verbose") {
		t.Error("expected hasFlag to not find --verbose")
	}
}
