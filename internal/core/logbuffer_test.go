package core

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// ─── NewLogRingBuffer ────────────────────────────────────────────────────────

func TestNewLogRingBuffer_Empty(t *testing.T) {
	b := NewLogRingBuffer(100)
	entries := b.GetEntries(10)
	if len(entries) != 0 {
		t.Errorf("new buffer should be empty, got %d entries", len(entries))
	}
}

func TestLogRingBuffer_Write_And_Get(t *testing.T) {
	b := NewLogRingBuffer(10)

	msg := `{"level":"info","message":"test"}`
	n, err := b.Write([]byte(msg))
	if err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	if n != len(msg) {
		t.Errorf("Write() returned %d, want %d", n, len(msg))
	}

	entries := b.GetEntries(1)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Raw != msg {
		t.Errorf("Raw = %q, want %q", entries[0].Raw, msg)
	}
	if entries[0].Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

func TestLogRingBuffer_GetEntries_FewerThanStored(t *testing.T) {
	b := NewLogRingBuffer(100)
	for i := 0; i < 5; i++ {
		b.Write([]byte("entry"))
	}
	entries := b.GetEntries(3)
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

func TestLogRingBuffer_GetEntries_MoreThanStored(t *testing.T) {
	b := NewLogRingBuffer(100)
	for i := 0; i < 3; i++ {
		b.Write([]byte("entry"))
	}
	entries := b.GetEntries(100)
	if len(entries) != 3 {
		t.Errorf("expected 3 entries (capped at stored count), got %d", len(entries))
	}
}

func TestLogRingBuffer_GetEntries_Zero(t *testing.T) {
	b := NewLogRingBuffer(100)
	b.Write([]byte("entry"))
	entries := b.GetEntries(0)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for n=0, got %d", len(entries))
	}
}

func TestLogRingBuffer_GetEntries_Negative(t *testing.T) {
	b := NewLogRingBuffer(100)
	b.Write([]byte("entry"))
	entries := b.GetEntries(-1)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for n=-1, got %d", len(entries))
	}
}

// ─── Ring Wrapping ───────────────────────────────────────────────────────────

func TestLogRingBuffer_Overflow_Wraps(t *testing.T) {
	maxSize := 5
	b := NewLogRingBuffer(maxSize)

	// Write maxSize+3 entries; the oldest 3 get overwritten
	for i := 0; i < maxSize+3; i++ {
		b.Write([]byte(itoa(i)))
	}

	entries := b.GetEntries(maxSize)
	if len(entries) != maxSize {
		t.Fatalf("expected %d entries after wrap, got %d", maxSize, len(entries))
	}

	// Oldest remaining entry should be "3" (0,1,2 overwritten)
	if entries[0].Raw != "3" {
		t.Errorf("expected oldest entry to be '3', got %q", entries[0].Raw)
	}
	// Most recent entry should be "7"
	if entries[maxSize-1].Raw != "7" {
		t.Errorf("expected newest entry to be '7', got %q", entries[maxSize-1].Raw)
	}
}

func TestLogRingBuffer_Full_Flag(t *testing.T) {
	b := NewLogRingBuffer(3)
	// Fill exactly
	b.Write([]byte("a"))
	b.Write([]byte("b"))
	b.Write([]byte("c"))

	entries := b.GetEntries(10)
	if len(entries) != 3 {
		t.Errorf("expected 3 entries after filling exactly, got %d", len(entries))
	}
}

// ─── Chronological Order ─────────────────────────────────────────────────────

func TestLogRingBuffer_GetEntries_ChronologicalOrder(t *testing.T) {
	b := NewLogRingBuffer(10)
	messages := []string{"first", "second", "third", "fourth", "fifth"}
	for _, msg := range messages {
		b.Write([]byte(msg))
		time.Sleep(time.Millisecond)
	}

	entries := b.GetEntries(len(messages))
	for i, want := range messages {
		if entries[i].Raw != want {
			t.Errorf("entries[%d].Raw = %q, want %q", i, entries[i].Raw, want)
		}
	}
}

func TestLogRingBuffer_GetEntries_ChronologicalOrder_AfterWrap(t *testing.T) {
	b := NewLogRingBuffer(3)
	// Write 5, creating wrap: slots become [3,4,2] → logical order [2,3,4]
	for i := 0; i < 5; i++ {
		b.Write([]byte(itoa(i)))
	}
	entries := b.GetEntries(3)
	if entries[0].Raw != "2" || entries[1].Raw != "3" || entries[2].Raw != "4" {
		t.Errorf("wrong order after wrap: %v", rawSlice(entries))
	}
}

// ─── MultiWriter ─────────────────────────────────────────────────────────────

func TestLogRingBuffer_MultiWriter(t *testing.T) {
	b := NewLogRingBuffer(10)
	var buf bytes.Buffer

	mw := b.MultiWriter(&buf)
	msg := "hello world"
	mw.Write([]byte(msg))

	// Should be in the ring buffer
	entries := b.GetEntries(1)
	if len(entries) == 0 {
		t.Fatal("expected entry in ring buffer")
	}
	if entries[0].Raw != msg {
		t.Errorf("ring buffer entry = %q, want %q", entries[0].Raw, msg)
	}

	// Should also be in the regular writer
	if buf.String() != msg {
		t.Errorf("regular writer = %q, want %q", buf.String(), msg)
	}
}

// ─── Concurrent Access ────────────────────────────────────────────────────────

func TestLogRingBuffer_ConcurrentSafe(t *testing.T) {
	b := NewLogRingBuffer(100)
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			b.Write([]byte("write"))
		}()
		go func() {
			defer wg.Done()
			b.GetEntries(5)
		}()
	}
	wg.Wait()
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func itoa(n int) string {
	return string(rune('0' + n))
}

func rawSlice(entries []LogEntry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Raw
	}
	return out
}
