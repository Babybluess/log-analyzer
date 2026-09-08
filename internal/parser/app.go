package parser

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Babybluess/log-analyzer/internal/model"
)

// appLogLine represents a JSON-structured application log line.
// Supports common fields from Winston, Pino, Zap, structlog, etc.
type appLogLine struct {
	Timestamp  interface{} `json:"timestamp"`
	Time       interface{} `json:"time"`
	Ts         interface{} `json:"ts"`
	Level      string      `json:"level"`
	Message    string      `json:"message"`
	Msg        string      `json:"msg"`
	IP         string      `json:"ip"`
	RemoteAddr string      `json:"remoteAddr"`
	Method     string      `json:"method"`
	Path       string      `json:"path"`
	URL        string      `json:"url"`
	Status     int         `json:"status"`
	StatusCode int         `json:"statusCode"`
	User       string      `json:"user"`
	UserID     string      `json:"userId"`
	UserAgent  string      `json:"userAgent"`
	Error      string      `json:"error"`
}

var timeFormats = []string{
	time.RFC3339,
	time.RFC3339Nano,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006/01/02 15:04:05",
}

func parseFlexTime(v interface{}) time.Time {
	if v == nil {
		return time.Time{}
	}
	switch val := v.(type) {
	case string:
		for _, f := range timeFormats {
			if t, err := time.Parse(f, val); err == nil {
				return t
			}
		}
	case float64:
		// Unix timestamp (seconds or milliseconds)
		if val > 1e12 {
			return time.UnixMilli(int64(val))
		}
		return time.Unix(int64(val), 0)
	}
	return time.Time{}
}

// ParseApp reads a newline-delimited JSON application log file.
func ParseApp(path string) ([]model.LogEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open app log: %w", err)
	}
	defer f.Close()
	return parseAppReader(f)
}

func parseAppReader(r io.Reader) ([]model.LogEntry, error) {
	var entries []model.LogEntry
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] != '{' {
			continue
		}

		var raw appLogLine
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		// Resolve timestamp from multiple possible fields
		tsVal := raw.Timestamp
		if tsVal == nil {
			tsVal = raw.Time
		}
		if tsVal == nil {
			tsVal = raw.Ts
		}
		ts := parseFlexTime(tsVal)

		// Resolve message
		msg := raw.Message
		if msg == "" {
			msg = raw.Msg
		}
		if msg == "" {
			msg = raw.Error
		}

		// Resolve IP
		ip := raw.IP
		if ip == "" {
			ip = raw.RemoteAddr
		}

		// Resolve path
		path := raw.Path
		if path == "" {
			path = raw.URL
		}

		// Resolve status
		status := raw.Status
		if status == 0 {
			status = raw.StatusCode
		}

		// Resolve user
		user := raw.User
		if user == "" {
			user = raw.UserID
		}

		entries = append(entries, model.LogEntry{
			Timestamp:  ts,
			Source:     model.SourceApp,
			IP:         ip,
			UserAgent:  raw.UserAgent,
			Method:     raw.Method,
			Path:       path,
			StatusCode: status,
			Message:    msg,
			User:       user,
			Raw:        line,
		})
	}

	return entries, scanner.Err()
}
