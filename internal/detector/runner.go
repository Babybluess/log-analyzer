// Package detector contains all threat detection rules.
// Each detector implements the Detector interface and receives
// the correlated session map to produce IOC findings.
package detector

import (
	"sort"

	"github.com/Babybluess/log-analyzer/internal/model"
)

// Detector is the interface all detection rules implement.
type Detector interface {
	Detect(sessions map[string][]model.Session) []model.IOC
}

// All returns all registered detectors in run order.
func All() []Detector {
	return []Detector{
		&AuthBruteForce{},
		&HighRequestRate{},
		&SQLiDetector{},
		&XSSDetector{},
		&ScannerDetector{},
		&SuspiciousUADetector{},
	}
}

// RunAll executes all detectors against the session map and returns
// deduplicated IOCs sorted by severity then count.
func RunAll(sessions map[string][]model.Session, detectors []Detector) []model.IOC {
	var all []model.IOC
	for _, d := range detectors {
		all = append(all, d.Detect(sessions)...)
	}
	return sortIOCs(all)
}

var severityOrder = map[model.Severity]int{
	model.SeverityCritical: 0,
	model.SeverityHigh:     1,
	model.SeverityMedium:   2,
	model.SeverityLow:      3,
	model.SeverityInfo:     4,
}

func sortIOCs(iocs []model.IOC) []model.IOC {
	sort.SliceStable(iocs, func(i, j int) bool {
		oi := severityOrder[iocs[i].Severity]
		oj := severityOrder[iocs[j].Severity]
		if oi != oj {
			return oi < oj
		}
		return iocs[i].Count > iocs[j].Count
	})
	return iocs
}
