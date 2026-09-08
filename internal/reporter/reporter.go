// Package reporter handles output formatting for analysis results.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Babybluess/log-analyzer/internal/model"
)

// PrintSummary prints a human-readable summary to stdout.
func PrintSummary(iocs []model.IOC, totalEntries int, duration time.Duration) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Fprintln(w, "  log-analyzer — IOC Analysis Report")
	fmt.Fprintf(w, "  Scanned: %d log entries   Analysis time: %s\n", totalEntries, duration.Round(time.Millisecond))
	fmt.Fprintln(w, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	if len(iocs) == 0 {
		fmt.Println("  ✅ No IOCs detected.")
		return
	}

	counts := map[model.Severity]int{}
	for _, ioc := range iocs {
		counts[ioc.Severity]++
	}

	fmt.Fprintf(w, "  Findings: CRITICAL=%d  HIGH=%d  MEDIUM=%d  LOW=%d\n\n",
		counts[model.SeverityCritical],
		counts[model.SeverityHigh],
		counts[model.SeverityMedium],
		counts[model.SeverityLow],
	)
	w.Flush()

	for _, ioc := range iocs {
		icon := severityIcon(ioc.Severity)
		fmt.Printf("%s [%s] %s\n", icon, ioc.Severity, ioc.Title)
		fmt.Printf("   Rule: %s  |  IP: %s  |  Events: %d\n", ioc.Rule, ioc.IP, ioc.Count)
		fmt.Printf("   Period: %s → %s\n",
			ioc.FirstSeen.Format("2006-01-02 15:04:05"),
			ioc.LastSeen.Format("15:04:05"),
		)
		// Wrap description
		desc := wordWrap(ioc.Description, 70)
		for _, line := range desc {
			fmt.Printf("   %s\n", line)
		}
		if len(ioc.Evidence) > 0 {
			fmt.Println("   Evidence:")
			for _, e := range ioc.Evidence {
				fmt.Printf("     > %s\n", e)
			}
		}
		fmt.Println()
	}
}

// WriteJSON writes IOCs as JSON to the given writer.
func WriteJSON(iocs []model.IOC, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(iocs)
}

// WriteJSONFile writes IOCs as JSON to a file.
func WriteJSONFile(iocs []model.IOC, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create json output: %w", err)
	}
	defer f.Close()
	return WriteJSON(iocs, f)
}

// WriteCSV writes a simple CSV summary of IOCs.
func WriteCSV(iocs []model.IOC, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create csv output: %w", err)
	}
	defer f.Close()

	fmt.Fprintln(f, "severity,rule,ip,title,count,first_seen,last_seen")
	for _, ioc := range iocs {
		fmt.Fprintf(f, "%s,%s,%s,%q,%d,%s,%s\n",
			ioc.Severity, ioc.Rule, ioc.IP,
			ioc.Title, ioc.Count,
			ioc.FirstSeen.Format(time.RFC3339),
			ioc.LastSeen.Format(time.RFC3339),
		)
	}
	return nil
}

func severityIcon(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "🔴"
	case model.SeverityHigh:
		return "🟠"
	case model.SeverityMedium:
		return "🟡"
	case model.SeverityLow:
		return "🔵"
	default:
		return "⚪"
	}
}

func wordWrap(s string, width int) []string {
	words := strings.Fields(s)
	var lines []string
	line := ""
	for _, w := range words {
		if len(line)+len(w)+1 > width && line != "" {
			lines = append(lines, line)
			line = w
		} else {
			if line == "" {
				line = w
			} else {
				line += " " + w
			}
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
