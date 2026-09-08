package detector

import (
	"fmt"
	"time"

	"github.com/Babybluess/log-analyzer/internal/model"
)

// HighRequestRate detects IPs sending unusually high request volumes per minute.
// Threshold: >= 100 req/min → MEDIUM, >= 300 req/min → HIGH
type HighRequestRate struct {
	MediumRPM float64 // default 100
	HighRPM   float64 // default 300
}

func (d *HighRequestRate) Detect(sessions map[string][]model.Session) []model.IOC {
	medRPM := d.MediumRPM
	if medRPM == 0 {
		medRPM = 100
	}
	highRPM := d.HighRPM
	if highRPM == 0 {
		highRPM = 300
	}

	var iocs []model.IOC

	for ip, slist := range sessions {
		for _, s := range slist {
			// Only count HTTP entries
			httpCount := 0
			var evidence []string
			for _, e := range s.Entries {
				if e.Source == model.SourceNginx {
					httpCount++
					if len(evidence) < 3 {
						evidence = append(evidence, e.Raw)
					}
				}
			}
			if httpCount == 0 {
				continue
			}

			duration := s.End.Sub(s.Start)
			if duration < time.Second {
				duration = time.Second
			}
			rpm := float64(httpCount) / duration.Minutes()

			if rpm < medRPM {
				continue
			}

			sev := model.SeverityMedium
			if rpm >= highRPM {
				sev = model.SeverityHigh
			}

			iocs = append(iocs, model.IOC{
				Rule:  "HIGH_REQUEST_RATE",
				Severity: sev,
				Title: fmt.Sprintf("Abnormal request rate from %s (%.0f req/min)", ip, rpm),
				Description: fmt.Sprintf(
					"IP %s sent %d HTTP requests in %s (%.1f req/min). "+
						"This may indicate a DDoS attack, scraper, or aggressive bot.",
					ip, httpCount, duration.Round(time.Second), rpm,
				),
				IP:        ip,
				Evidence:  evidence,
				Count:     httpCount,
				FirstSeen: s.Start,
				LastSeen:  s.End,
			})
		}
	}
	return iocs
}
