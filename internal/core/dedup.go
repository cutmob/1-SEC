package core

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// EventDedup is a short-lived deduplication cache that prevents the same event
// from being processed twice (e.g., when syslog listener and a collector both
// ingest the same log line). Uses a hash of (type + source_ip + summary +
// raw_data prefix) with a configurable TTL.
type EventDedup struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	ttl     time.Duration
	maxSize int
}

// NewEventDedup creates a dedup cache. TTL controls how long a hash is
// remembered. maxSize caps memory usage by evicting oldest entries.
func NewEventDedup(ttl time.Duration, maxSize int) *EventDedup {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if maxSize <= 0 {
		maxSize = 50000
	}
	d := &EventDedup{
		seen:    make(map[string]time.Time, maxSize/2),
		ttl:     ttl,
		maxSize: maxSize,
	}
	return d
}

// IsDuplicate returns true if this event was seen within the TTL window.
// If not a duplicate, it records the event hash.
func (d *EventDedup) IsDuplicate(event *SecurityEvent) bool {
	hash := d.hash(event)

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	// Check if seen and still within TTL
	if seenAt, ok := d.seen[hash]; ok {
		if now.Sub(seenAt) < d.ttl {
			return true
		}
	}

	// Record and evict if over capacity
	d.seen[hash] = now
	if len(d.seen) > d.maxSize {
		d.evictLocked(now)
	}

	return false
}

// hash produces a compact fingerprint of the event. We use type + source_ip +
// first 128 bytes of summary + first 256 bytes of raw data. This catches
// duplicate syslog lines without being too expensive.
func (d *EventDedup) hash(event *SecurityEvent) string {
	h := sha256.New()
	h.Write([]byte(event.Type))
	h.Write([]byte{0})
	h.Write([]byte(event.SourceIP))
	h.Write([]byte{0})

	summary := event.Summary
	if len(summary) > 128 {
		summary = summary[:128]
	}
	h.Write([]byte(summary))
	h.Write([]byte{0})

	if len(event.RawData) > 0 {
		raw := event.RawData
		if len(raw) > 256 {
			raw = raw[:256]
		}
		h.Write(raw)
	}

	return hex.EncodeToString(h.Sum(nil)[:16]) // 128-bit hash is plenty
}

// evictLocked removes entries older than TTL. Called when cache exceeds maxSize.
func (d *EventDedup) evictLocked(now time.Time) {
	for k, t := range d.seen {
		if now.Sub(t) >= d.ttl {
			delete(d.seen, k)
		}
	}
	// If still over capacity after TTL eviction, drop oldest half
	if len(d.seen) > d.maxSize {
		count := 0
		target := len(d.seen) / 2
		for k := range d.seen {
			delete(d.seen, k)
			count++
			if count >= target {
				break
			}
		}
	}
}

// StartCleanup runs a background goroutine that periodically evicts expired
// entries. Call the returned function to stop it.
func (d *EventDedup) StartCleanup(interval time.Duration) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				d.mu.Lock()
				now := time.Now()
				for k, t := range d.seen {
					if now.Sub(t) >= d.ttl {
						delete(d.seen, k)
					}
				}
				d.mu.Unlock()
			}
		}
	}()
	return func() { close(done) }
}

// Size returns the current number of entries in the cache.
func (d *EventDedup) Size() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}
