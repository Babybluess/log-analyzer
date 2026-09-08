package detector

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Babybluess/log-analyzer/internal/model"
)

// ScannerDetector detects automated vulnerability scanners, path traversal,
// and reconnaissance activity.
var scannerPatterns = []*regexp.Regexp{
	// Path traversal
	regexp.MustCompile(`\.\./|\.\.\\`),
	regexp.MustCompile(`%2e%2e%2f|%2e%2e/|\.\.%2f`),
	// Sensitive file probing
	regexp.MustCompile(`(?i)(\/etc\/passwd|\/etc\/shadow|\/proc\/self)`),
	regexp.MustCompile(`(?i)(\.env|\.git\/config|\.git\/HEAD|phpinfo\.php)`),
	regexp.MustCompile(`(?i)(wp-admin|wp-login|xmlrpc\.php)`),
	regexp.MustCompile(`(?i)(\.aws\/credentials|web\.config|app\.config)`),
	// Known scanner UA strings
	regexp.MustCompile(`(?i)(nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|sqlmap|acunetix|nessus|openvas|burpsuite|wfuzz|ffuf)`),
	// Shell/code injection probes
	regexp.MustCompile(`(?i)(\$\{.*\}|%24%7b)`),                  // Template injection
	regexp.MustCompile(`(?i)(eval\s*\(|base64_decode\s*\()`),     // PHP RCE
	regexp.MustCompile(`(?i)(/bin/sh|/bin/bash|cmd\.exe|powershell)`), // Shell
}

var knownScannerUAs = []string{
	"nikto", "nmap", "masscan", "zgrab", "nuclei", "gobuster",
	"dirbuster", "sqlmap", "acunetix", "nessus", "openvas",
	"wfuzz", "ffuf", "hydra", "medusa",
}

type ScannerDetector struct{}

func (d *ScannerDetector) Detect(sessions map[string][]model.Session) []model.IOC {
	type ipStats struct {
		count    int
		evidence []string
		reasons  map[string]int
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
				reason := ""

				for _, re := range scannerPatterns {
					if re.MatchString(target) {
						reason = re.String()
						break
					}
				}
				// Also check UA directly
				uaLower := strings.ToLower(e.UserAgent)
				for _, ua := range knownScannerUAs {
					if strings.Contains(uaLower, ua) {
						reason = "known-scanner-ua:" + ua
						break
					}
				}

				if reason == "" {
					continue
				}

				st := stats[ip]
				if st == nil {
					st = &ipStats{first: e, last: e, reasons: make(map[string]int)}
					stats[ip] = st
				}
				st.count++
				st.last = e
				st.reasons[reason]++
				if len(st.evidence) < 5 {
					st.evidence = append(st.evidence, fmt.Sprintf("[%s] %s %s (UA: %s)",
						e.Timestamp.Format("15:04:05"), e.Method, e.Path, e.UserAgent))
				}
			}
		}
	}

	var iocs []model.IOC
	for ip, st := range stats {
		sev := model.SeverityMedium
		if st.count >= 20 {
			sev = model.SeverityHigh
		}

		iocs = append(iocs, model.IOC{
			Rule:     "SCANNER_DETECTED",
			Severity: sev,
			Title:    fmt.Sprintf("Vulnerability scanner / path traversal from %s (%d probes)", ip, st.count),
			Description: fmt.Sprintf(
				"IP %s sent %d request(s) matching scanner signatures: "+
					"path traversal patterns, sensitive file probes, known scanner User-Agent strings, "+
					"or shell injection probes.",
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
