// Package model defines shared data structures used across all log-analyzer packages.
package model

import "time"

// LogSource identifies the type of log file being parsed.
type LogSource string

const (
	SourceNginx LogSource = "nginx"
	SourceAuth  LogSource = "auth"
	SourceApp   LogSource = "app"
)

// LogEntry is a normalised log event regardless of source format.
type LogEntry struct {
	Timestamp  time.Time
	Source     LogSource
	IP         string
	UserAgent  string
	Method     string // HTTP method (GET, POST, …)
	Path       string // Request path or endpoint
	StatusCode int
	BodyBytes  int
	Message    string // Raw message / auth message
	User       string // Username for auth logs
	Success    bool   // Auth success/failure
	Raw        string // Original line
}

// Severity levels for IOC findings.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// IOC (Indicator of Compromise) represents a detected threat signal.
type IOC struct {
	Rule        string    // Detector rule name
	Severity    Severity
	Title       string
	Description string
	IP          string
	User        string
	Evidence    []string // Sample log lines
	Count       int      // Number of events
	FirstSeen   time.Time
	LastSeen    time.Time
}

// Session groups log entries by IP + session window.
type Session struct {
	IP      string
	Entries []LogEntry
	Start   time.Time
	End     time.Time
}
