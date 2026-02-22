package main

import (
	"strings"
	"testing"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
		{104857600, "100.0 MB"},
		{1099511627776, "1.0 TB"},
	}
	for _, tc := range tests {
		got := formatBytes(tc.input)
		if got != tc.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestBoolStatus_True(t *testing.T) {
	got := boolStatus(true)
	if !strings.Contains(got, "connected") {
		t.Errorf("boolStatus(true) = %q, want to contain 'connected'", got)
	}
}

func TestBoolStatus_False(t *testing.T) {
	got := boolStatus(false)
	if !strings.Contains(got, "disconnected") {
		t.Errorf("boolStatus(false) = %q, want to contain 'disconnected'", got)
	}
}

func TestBoolStatus_NonBool(t *testing.T) {
	got := boolStatus("unknown")
	if !strings.Contains(got, "unknown") {
		t.Errorf("boolStatus(\"unknown\") = %q, want to contain 'unknown'", got)
	}
}

func TestBoolStatus_Nil(t *testing.T) {
	got := boolStatus(nil)
	if got == "" {
		t.Error("boolStatus(nil) should return a non-empty string")
	}
}
