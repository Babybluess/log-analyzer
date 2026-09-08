package detector

import (
	"fmt"
	"regexp"

	"github.com/Babybluess/log-analyzer/internal/model"
)

var xssSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[\s>]`),
	regexp.MustCompile(`(?i)javascript\s*:`),
	regexp.MustCompile(`(?i)on(load|click|error|mouseover|focus|blur|change|submit)\s*=`),
	regexp.MustCompile(`(?i)<\s*(img|svg|iframe|body|input)\s[^>]*(src|href)\s*=\s*['"]?\s*javascript`),
	regexp.MustCompile(`(?i)(alert|confirm|prompt)\s*\(`),
	regexp.MustCompile(`(?i)<\s*svg\s[^>]*on\w+\s*=`),
	regexp.MustCompile(`(?i)%3cscript|%3c%2fscript`), // URL-encoded <script>
	regexp.MustCompile(`(?i)&#x?[0-9a-f]+;.*(script|alert)`),
}

// XSSDetector finds XSS payloads in HTTP request paths.
type XSSDetector struct{}

func (d *XSSDetector) Detect(sessions map[string][]model.Session) []model.IOC {
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
				hit := false
				for _, re := range xssSignatures {
					if re.MatchString(target) {
						hit = true
						break
					}
				}
				if !hit {
					continue
				}
				st := stats[ip]
				if st == nil {
					st = &ipStats{first: e, last: e}
					stats[ip] = st
				}
				st.count++
				st.last = e
				if len(st.evidence) < 5 {
					st.evidence = append(st.evidence, fmt.Sprintf("[%s] %s %s",
						e.Timestamp.Format("15:04:05"), e.Method, e.Path))
				}
			}
		}
	}

	var iocs []model.IOC
	for ip, st := range stats {
		iocs = append(iocs, model.IOC{
			Rule:     "XSS_ATTEMPT",
			Severity: model.SeverityHigh,
			Title:    fmt.Sprintf("XSS injection attempts from %s (%d requests)", ip, st.count),
			Description: fmt.Sprintf(
				"IP %s sent %d request(s) with XSS payloads in the URL path or User-Agent header. "+
					"Patterns matched include: script tags, event handlers, javascript: URI, and encoded variants.",
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
