// log-analyzer — SIEM-style log correlation and IOC extraction tool.
// Author: Hoang Minh Thang (github.com/Babybluess)
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Babybluess/log-analyzer/internal/correlator"
	"github.com/Babybluess/log-analyzer/internal/detector"
	"github.com/Babybluess/log-analyzer/internal/model"
	"github.com/Babybluess/log-analyzer/internal/parser"
	"github.com/Babybluess/log-analyzer/internal/reporter"
)

func main() {
	// --- Flags ---
	nginxFlag  := flag.String("nginx", "", "Path to nginx access log file")
	authFlag   := flag.String("auth", "", "Path to auth.log / secure file")
	appFlag    := flag.String("app", "", "Path to JSON application log file")
	windowFlag := flag.Duration("window", 10*time.Minute, "Session correlation window (e.g. 5m, 30m)")
	outJSON    := flag.String("json", "", "Write IOC findings to JSON file")
	outCSV     := flag.String("csv", "", "Write IOC findings to CSV file")
	minSev     := flag.String("min-severity", "LOW", "Minimum severity to display: CRITICAL|HIGH|MEDIUM|LOW|INFO")
	flag.Usage = usage
	flag.Parse()

	if *nginxFlag == "" && *authFlag == "" && *appFlag == "" {
		fmt.Fprintln(os.Stderr, "error: provide at least one log file (--nginx, --auth, or --app)")
		flag.Usage()
		os.Exit(1)
	}

	start := time.Now()

	// --- Parse ---
	var allEntries []model.LogEntry

	if *nginxFlag != "" {
		fmt.Fprintf(os.Stderr, "📂 Parsing nginx log: %s\n", *nginxFlag)
		entries, err := parser.ParseNginx(*nginxFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing nginx log: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "   → %d entries\n", len(entries))
		allEntries = append(allEntries, entries...)
	}

	if *authFlag != "" {
		fmt.Fprintf(os.Stderr, "📂 Parsing auth log: %s\n", *authFlag)
		entries, err := parser.ParseAuth(*authFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing auth log: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "   → %d entries\n", len(entries))
		allEntries = append(allEntries, entries...)
	}

	if *appFlag != "" {
		fmt.Fprintf(os.Stderr, "📂 Parsing app log: %s\n", *appFlag)
		entries, err := parser.ParseApp(*appFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing app log: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "   → %d entries\n", len(entries))
		allEntries = append(allEntries, entries...)
	}

	if len(allEntries) == 0 {
		fmt.Fprintln(os.Stderr, "⚠️  No log entries parsed. Check file paths and formats.")
		os.Exit(0)
	}

	// --- Correlate ---
	fmt.Fprintln(os.Stderr, "🔗 Correlating sessions...")
	cfg := correlator.Config{WindowSize: *windowFlag}
	sessions := correlator.Correlate(allEntries, cfg)
	fmt.Fprintf(os.Stderr, "   → %d unique IP(s), %d session(s)\n",
		len(sessions), countSessions(sessions))

	// --- Detect ---
	fmt.Fprintln(os.Stderr, "🔍 Running detection rules...")
	iocs := detector.RunAll(sessions, detector.All())

	// Filter by min severity
	iocs = filterBySeverity(iocs, *minSev)

	elapsed := time.Since(start)

	// --- Report ---
	reporter.PrintSummary(iocs, len(allEntries), elapsed)

	if *outJSON != "" {
		if err := reporter.WriteJSONFile(iocs, *outJSON); err != nil {
			fmt.Fprintf(os.Stderr, "error writing JSON: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "💾 JSON report: %s\n", *outJSON)
		}
	}

	if *outCSV != "" {
		if err := reporter.WriteCSV(iocs, *outCSV); err != nil {
			fmt.Fprintf(os.Stderr, "error writing CSV: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "💾 CSV report: %s\n", *outCSV)
		}
	}

	// Exit code: 2 = CRITICAL findings, 1 = HIGH, 0 = clean
	for _, ioc := range iocs {
		if ioc.Severity == model.SeverityCritical {
			os.Exit(2)
		}
	}
	for _, ioc := range iocs {
		if ioc.Severity == model.SeverityHigh {
			os.Exit(1)
		}
	}
}

func countSessions(m map[string][]model.Session) int {
	n := 0
	for _, ss := range m {
		n += len(ss)
	}
	return n
}

func filterBySeverity(iocs []model.IOC, minSev string) []model.IOC {
	order := map[model.Severity]int{
		model.SeverityCritical: 0,
		model.SeverityHigh:     1,
		model.SeverityMedium:   2,
		model.SeverityLow:      3,
		model.SeverityInfo:     4,
	}
	threshold, ok := order[model.Severity(strings.ToUpper(minSev))]
	if !ok {
		threshold = 3 // default LOW
	}
	var out []model.IOC
	for _, ioc := range iocs {
		if order[ioc.Severity] <= threshold {
			out = append(out, ioc)
		}
	}
	return out
}

func usage() {
	fmt.Fprintln(os.Stderr, `
log-analyzer — SIEM-style log correlation and IOC extraction tool
Author: Hoang Minh Thang (github.com/Babybluess)

Usage:
  log-analyzer [flags]

Flags:
  --nginx   <path>    Nginx access log (combined format)
  --auth    <path>    Linux auth.log / secure file
  --app     <path>    Newline-delimited JSON application log
  --window  <dur>     Session correlation window (default: 10m)
  --json    <path>    Write IOC findings to JSON file
  --csv     <path>    Write IOC findings to CSV file
  --min-severity      Minimum severity to display: CRITICAL|HIGH|MEDIUM|LOW|INFO (default: LOW)

Examples:
  log-analyzer --nginx /var/log/nginx/access.log
  log-analyzer --nginx access.log --auth auth.log --window 5m
  log-analyzer --nginx access.log --json findings.json --csv findings.csv
  log-analyzer --nginx access.log --min-severity HIGH

Exit codes:
  0 = no HIGH/CRITICAL findings
  1 = HIGH findings detected
  2 = CRITICAL findings detected
`)
}
