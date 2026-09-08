package detector

import (
	"fmt"

	"github.com/Babybluess/log-analyzer/internal/model"
)

// AuthBruteForce detects IPs with many failed authentication attempts.
// Threshold: >= 5 failures in a session → HIGH
//            >= 10 failures              → CRITICAL
type AuthBruteForce struct {
	LowThreshold  int // default 5
	HighThreshold int // default 10
}

func (d *AuthBruteForce) thresholds() (int, int) {
	low := d.LowThreshold
	if low == 0 {
		low = 5
	}
	high := d.HighThreshold
	if high == 0 {
		high = 10
	}
	return low, high
}

func (d *AuthBruteForce) Detect(sessions map[string][]model.Session) []model.IOC {
	low, high := d.thresholds()
	var iocs []model.IOC

	for ip, slist := range sessions {
		for _, s := range slist {
			failures := 0
			var evidence []string
			var users []string

			for _, e := range s.Entries {
				if e.Source == model.SourceAuth && !e.Success {
					failures++
					if len(evidence) < 5 {
						evidence = append(evidence, e.Raw)
					}
					if e.User != "" {
						users = append(users, e.User)
					}
				}
			}

			if failures < low {
				continue
			}

			sev := model.SeverityHigh
			if failures >= high {
				sev = model.SeverityCritical
			}

			uniqueUsers := unique(users)

			iocs = append(iocs, model.IOC{
				Rule:     "AUTH_BRUTE_FORCE",
				Severity: sev,
				Title:    fmt.Sprintf("Brute-force attack from %s (%d failed logins)", ip, failures),
				Description: fmt.Sprintf(
					"IP %s made %d failed authentication attempts in a %s window. "+
						"Targeted user(s): %v. This pattern is consistent with a credential brute-force or password spray attack.",
					ip, failures, s.End.Sub(s.Start).Round(1e9), uniqueUsers,
				),
				IP:        ip,
				Evidence:  evidence,
				Count:     failures,
				FirstSeen: s.Start,
				LastSeen:  s.End,
			})
		}
	}
	return iocs
}

func unique(ss []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range ss {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
