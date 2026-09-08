package parser

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Babybluess/log-analyzer/internal/model"
)

// Matches Linux auth.log / secure lines
// e.g.: "Sep  8 12:34:56 hostname sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
var authPattern = regexp.MustCompile(
	`^(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+\S+:\s+(.+)$`,
)

var (
	authFailRe    = regexp.MustCompile(`(?i)failed\s+password\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)`)
	authSuccessRe = regexp.MustCompile(`(?i)accepted\s+(?:password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)`)
	sudoFailRe    = regexp.MustCompile(`(?i)authentication failure.*user=(\S+)`)
	invalidUserRe = regexp.MustCompile(`(?i)invalid user\s+(\S+)\s+from\s+(\S+)`)
)

const authTimeFormat = "Jan  2 15:04:05"
const authTimeFormat2 = "Jan 2 15:04:05"

func parseAuthTime(s string) time.Time {
	s = strings.TrimSpace(s)
	// Normalise double-space month padding
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	now := time.Now()
	// Try with current year
	for _, layout := range []string{"Jan 2 15:04:05", "Jan  2 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.AddDate(now.Year(), 0, 0)
		}
	}
	return time.Time{}
}

// ParseAuth reads a Linux auth.log / secure file.
func ParseAuth(path string) ([]model.LogEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open auth log: %w", err)
	}
	defer f.Close()
	return parseAuthReader(f)
}

func parseAuthReader(r io.Reader) ([]model.LogEntry, error) {
	var entries []model.LogEntry
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		m := authPattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ts := parseAuthTime(m[1])
		msg := m[2]

		entry := model.LogEntry{
			Timestamp: ts,
			Source:    model.SourceAuth,
			Message:   msg,
			Raw:       line,
		}

		if sub := authFailRe.FindStringSubmatch(msg); sub != nil {
			entry.User = sub[1]
			entry.IP = sub[2]
			entry.Success = false
		} else if sub := authSuccessRe.FindStringSubmatch(msg); sub != nil {
			entry.User = sub[1]
			entry.IP = sub[2]
			entry.Success = true
		} else if sub := invalidUserRe.FindStringSubmatch(msg); sub != nil {
			entry.User = sub[1]
			entry.IP = sub[2]
			entry.Success = false
		} else if sub := sudoFailRe.FindStringSubmatch(msg); sub != nil {
			entry.User = sub[1]
			entry.Success = false
		} else {
			continue // skip unrecognised auth lines
		}

		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}
