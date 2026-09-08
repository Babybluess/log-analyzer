package detector

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Babybluess/log-analyzer/internal/model"
)

// SQLiPattern detects SQL injection attempts in HTTP request paths and query strings.
var sqliSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)('\s*(or|and)\s*'?\d+\s*=\s*\d+)`),   // ' OR 1=1
	regexp.MustCompile(`(?i)(union\s+(all\s+)?select)`),            // UNION SELECT
	regexp.MustCompile(`(?i)(select\s+.+\s+from\s+)`),              // SELECT … FROM
	regexp.MustCompile(`(?i)(insert\s+into|update\s+\w+\s+set)`),   // INSERT/UPDATE
	regexp.MustCompile(`(?i)(drop\s+table|drop\s+database)`),        // DROP TABLE
	regexp.MustCompile(`(?i)(sleep\s*\(\s*\d+\s*\))`),             // SLEEP(n)
	regexp.MustCompile(`(?i)(pg_sleep|waitfor\s+delay)`),           // pg_sleep / WAITFOR
	regexp.MustCompile(`(?i)(benchmark\s*\()`),                      // BENCHMARK()
	regexp.MustCompile(`(?i)(%27|%22|%3b|%2b).*(select|union|insert|drop)(?i)`), // URL-encoded
	regexp.MustCompile(`(?i)(char\s*\(\s*\d+)`),                    // CHAR() injection
	regexp.MustCompile(`(?i)(exec\s*\(|execute\s*\()`),             // EXEC()
	regexp.MustCompile(`--\s`),                                      // SQL comment
	regexp.MustCompile(`;\s*(drop|select|insert|update|delete)`),    // Stacked queries
}

// SQLiDetector finds SQL injection patterns in request paths.
type SQLiDetector struct{}

func (d *SQLiDetector) Detect(sessions map[string][]model.Session) []model.IOC {
	// Track per-IP findings to deduplicate
	type ipStats struct {
		count    int
		evidence []string
		first    model.LogEntry
		last     model.LogEntry
	}
	stats := make(map[string]*ipStats)

	for ip, slist := range sessions {
		for _, s := range slist {
			for _, e := range s.Entries {
				if e.Source != model.SourceNginx {
					continue
				}
				target := e.Path + " " + e.UserAgent
				if matchesSQLi(target) {
					st := stats[ip]
					if st == nil {
						st = &ipStats{first: e, last: e}
						stats[ip] = st
					}
					st.count++
					st.last = e
					if len(st.evidence) < 5 {
						st.evidence = append(st.evidence, fmt.Sprintf("[%s] %s %s → %d",
							e.Timestamp.Format("15:04:05"), e.Method, e.Path, e.StatusCode))
					}
				}
			}
		}
	}

	var iocs []model.IOC
	for ip, st := range stats {
		sev := model.SeverityHigh
		if st.count >= 10 {
			sev = model.SeverityCritical
		}
		iocs = append(iocs, model.IOC{
			Rule:     "SQLI_ATTEMPT",
			Severity: sev,
			Title:    fmt.Sprintf("SQL injection attempts from %s (%d requests)", ip, st.count),
			Description: fmt.Sprintf(
				"IP %s made %d request(s) containing SQL injection patterns. "+
					"These match signatures for UNION-based, error-based, time-based blind, and stacked-query SQLi.",
				ip, st.count,
			),
			IP:        ip,
			Evidence:  st.evidence,
			Count:     st.count,
			FirstSeen: st.first.Timestamp,
			LastSeen:  st.last.Timestamp,
		})
	}
	return iocs
}

func matchesSQLi(s string) bool {
	lower := strings.ToLower(s)
	for _, re := range sqliSignatures {
		if re.MatchString(lower) {
			return true
		}
	}
	return false
}
