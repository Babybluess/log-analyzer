package detector

import (
	"fmt"
	"strings"

	"github.com/Babybluess/log-analyzer/internal/model"
)

// SuspiciousUADetector flags empty, curl/wget, or abnormally short User-Agent strings
// that may indicate scripted attacks or bots.
type SuspiciousUADetector struct{}

func (d *SuspiciousUADetector) Detect(sessions map[string][]model.Session) []model.IOC {
	type ipStats struct {
		count    int
		evidence []string
		uas      map[string]int
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
				ua := strings.TrimSpace(e.UserAgent)
				suspicious := false
				reason := ""

				switch {
				case ua == "" || ua == "-":
					suspicious = true
					reason = "empty/missing UA"
				case len(ua) < 10:
					suspicious = true
					reason = fmt.Sprintf("very short UA (%d chars)", len(ua))
				case strings.HasPrefix(strings.ToLower(ua), "curl/") ||
					strings.HasPrefix(strings.ToLower(ua), "wget/") ||
					strings.HasPrefix(strings.ToLower(ua), "python-requests") ||
					strings.HasPrefix(strings.ToLower(ua), "go-http-client"):
					suspicious = true
					reason = "scripted client UA: " + ua
				}

				if !suspicious {
					continue
				}
				_ = reason

				st := stats[ip]
				if st == nil {
					st = &ipStats{first: e, last: e, uas: make(map[string]int)}
					stats[ip] = st
				}
				st.count++
				st.last = e
				st.uas[ua]++
				if len(st.evidence) < 3 {
					st.evidence = append(st.evidence, fmt.Sprintf("[%s] UA=%q path=%s",
						e.Timestamp.Format("15:04:05"), ua, e.Path))
				}
			}
		}
	}

	var iocs []model.IOC
	for ip, st := range stats {
		if st.count < 3 {
			continue // Ignore isolated curl requests
		}
		iocs = append(iocs, model.IOC{
			Rule:     "SUSPICIOUS_USERAGENT",
			Severity: model.SeverityLow,
			Title:    fmt.Sprintf("Suspicious User-Agent from %s (%d requests)", ip, st.count),
			Description: fmt.Sprintf(
				"IP %s made %d requests with empty, scripted, or abnormally short User-Agent strings. "+
					"This may indicate automated tools, bots, or attack scripts.",
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
