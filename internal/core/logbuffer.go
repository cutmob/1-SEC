package core

import (
	"io"
	"sync"
	"time"
)

// LogEntry represents a single log line captured by the engine.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Component string    `json:"component,omitempty"`
	Message   string    `json:"message"`
	Raw       string    `json:"raw"`
}

// LogRingBuffer is a fixed-size ring buffer that captures log output.
type LogRingBuffer struct {
	mu      sync.RWMutex
	entries []LogEntry
	maxSize int
	pos     int
	full    bool
}

// NewLogRingBuffer creates a ring buffer that holds up to maxSize entries.
func NewLogRingBuffer(maxSize int) *LogRingBuffer {
	return &LogRingBuffer{
		entries: make([]LogEntry, maxSize),
		maxSize: maxSize,
	}
}

// Write implements io.Writer so the buffer can be used as a zerolog output.
func (b *LogRingBuffer) Write(p []byte) (n int, err error) {
	line := string(p)
	entry := LogEntry{
		Timestamp: time.Now().UTC(),
		Raw:       line,
		Message:   line,
	}

	b.mu.Lock()
	b.entries[b.pos] = entry
	b.pos = (b.pos + 1) % b.maxSize
	if b.pos == 0 {
		b.full = true
	}
	b.mu.Unlock()

	return len(p), nil
}

// GetEntries returns the most recent n log entries in chronological order.
func (b *LogRingBuffer) GetEntries(n int) []LogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var total int
	if b.full {
		total = b.maxSize
	} else {
		total = b.pos
	}

	if n > total {
		n = total
	}
	if n <= 0 {
		return []LogEntry{}
	}

	result := make([]LogEntry, n)
	start := b.pos - n
	if start < 0 {
		start += b.maxSize
	}
	for i := 0; i < n; i++ {
		idx := (start + i) % b.maxSize
		result[i] = b.entries[idx]
	}
	return result
}

// MultiWriter returns an io.Writer that writes to both the log buffer and the given writer.
func (b *LogRingBuffer) MultiWriter(w io.Writer) io.Writer {
	return io.MultiWriter(w, b)
}
