// Package parser handles parsing of different log file formats into normalised LogEntry structs.
package parser

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Babybluess/log-analyzer/internal/model"
)

// nginxPattern matches the default nginx combined log format:
// $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
var nginxPattern = regexp.MustCompile(
	`^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"`,
)

// nginxTimeFormat is the time format used in nginx logs.
const nginxTimeFormat = "02/Jan/2006:15:04:05 -0700"

// ParseNginx reads a nginx access log file and returns normalised LogEntry slice.
func ParseNginx(path string) ([]model.LogEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open nginx log: %w", err)
	}
	defer f.Close()
	return parseNginxReader(f)
}

func parseNginxReader(r io.Reader) ([]model.LogEntry, error) {
	var entries []model.LogEntry
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		m := nginxPattern.FindStringSubmatch(line)
		if m == nil {
			continue // skip unparseable lines
		}

		ip := m[1]
		timeStr := m[3]
		request := m[4]
		statusStr := m[5]
		bytesStr := m[6]
		ua := m[8]

		ts, err := time.Parse(nginxTimeFormat, timeStr)
		if err != nil {
			ts = time.Time{}
		}

		status, _ := strconv.Atoi(statusStr)
		bodyBytes, _ := strconv.Atoi(bytesStr)

		// Parse request line: "METHOD /path HTTP/1.1"
		method, path := "", ""
		parts := strings.SplitN(request, " ", 3)
		if len(parts) >= 2 {
			method = parts[0]
			path = parts[1]
		}

		// Decode URL path for SQLi/XSS detection
		decoded, _ := url.QueryUnescape(path)

		entries = append(entries, model.LogEntry{
			Timestamp:  ts,
			Source:     model.SourceNginx,
			IP:         ip,
			UserAgent:  ua,
			Method:     method,
			Path:       decoded,
			StatusCode: status,
			BodyBytes:  bodyBytes,
			Raw:        line,
		})
	}

	return entries, scanner.Err()
}
