package logbuffer

import (
	"sync"
	"time"
)

// LogEntry defines the format of a log entry for the API.
type LogEntry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
	Error   string    `json:"error,omitempty"`
}

// RingBuffer is a fixed-size, thread-safe buffer for log entries.
type RingBuffer struct {
	entries []LogEntry
	size    int
	start   int
	count   int
	mu      sync.Mutex
}

// NewRingBuffer creates a new ring buffer of the given size.
func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{
		entries: make([]LogEntry, size),
		size:    size,
	}
}

// Add adds a log entry to the buffer.
func (rb *RingBuffer) Add(entry LogEntry) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.entries[(rb.start+rb.count)%rb.size] = entry
	if rb.count < rb.size {
		rb.count++
	} else {
		rb.start = (rb.start + 1) % rb.size
	}
}

// GetAll returns a slice of all log entries in order.
func (rb *RingBuffer) GetAll() []LogEntry {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	result := make([]LogEntry, rb.count)
	for i := 0; i < rb.count; i++ {
		result[i] = rb.entries[(rb.start+i)%rb.size]
	}
	return result
}

// GetFiltered returns log entries filtered by level and limited in count (most recent first).
func (rb *RingBuffer) GetFiltered(level string, limit int) []LogEntry {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	var filtered []LogEntry
	for i := rb.count - 1; i >= 0; i-- {
		entry := rb.entries[(rb.start+i)%rb.size]
		if level == "" || entry.Level == level {
			filtered = append(filtered, entry)
			if limit > 0 && len(filtered) >= limit {
				break
			}
		}
	}
	// Reverse to chronological order
	for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
		filtered[i], filtered[j] = filtered[j], filtered[i]
	}
	return filtered
}
