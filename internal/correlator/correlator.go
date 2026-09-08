// Package correlator groups log entries into sessions by IP address
// within a configurable time window. This is the core SIEM correlation logic.
package correlator

import (
	"sort"
	"time"

	"github.com/Babybluess/log-analyzer/internal/model"
)

// Config holds correlator settings.
type Config struct {
	// WindowSize is the maximum gap between events to be in the same session.
	WindowSize time.Duration
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		WindowSize: 10 * time.Minute,
	}
}

// Correlate groups entries by IP into sessions within the time window.
// Returns a map of IP → []Session.
func Correlate(entries []model.LogEntry, cfg Config) map[string][]model.Session {
	// Group by IP first
	byIP := make(map[string][]model.LogEntry)
	for _, e := range entries {
		if e.IP == "" {
			continue
		}
		byIP[e.IP] = append(byIP[e.IP], e)
	}

	result := make(map[string][]model.Session)

	for ip, evts := range byIP {
		// Sort by timestamp
		sort.Slice(evts, func(i, j int) bool {
			return evts[i].Timestamp.Before(evts[j].Timestamp)
		})

		var sessions []model.Session
		var current *model.Session

		for _, e := range evts {
			if current == nil {
				s := model.Session{IP: ip, Start: e.Timestamp, End: e.Timestamp}
				s.Entries = append(s.Entries, e)
				current = &s
				continue
			}

			gap := e.Timestamp.Sub(current.End)
			if gap <= cfg.WindowSize {
				current.Entries = append(current.Entries, e)
				if e.Timestamp.After(current.End) {
					current.End = e.Timestamp
				}
			} else {
				sessions = append(sessions, *current)
				s := model.Session{IP: ip, Start: e.Timestamp, End: e.Timestamp}
				s.Entries = append(s.Entries, e)
				current = &s
			}
		}

		if current != nil {
			sessions = append(sessions, *current)
		}

		result[ip] = sessions
	}

	return result
}

// FlatEntries returns all entries sorted by timestamp (for global analysis).
func FlatEntries(sessions map[string][]model.Session) []model.LogEntry {
	var all []model.LogEntry
	for _, slist := range sessions {
		for _, s := range slist {
			all = append(all, s.Entries...)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].Timestamp.Before(all[j].Timestamp)
	})
	return all
}
