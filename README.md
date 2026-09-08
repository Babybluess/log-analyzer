# log-analyzer

SIEM-style log correlation and IOC (Indicator of Compromise) extraction tool written in Go.

Parses nginx access logs, Linux auth logs, and JSON application logs — correlates events by IP and session window — then runs detection rules to surface threat signals with severity ratings.

---

## Features

| Detector | What it finds | Severity |
|---|---|---|
| **Auth Brute Force** | SSH/login failures from same IP (≥5 = HIGH, ≥10 = CRITICAL) | CRITICAL / HIGH |
| **High Request Rate** | Abnormal HTTP request volume (≥100 req/min = MEDIUM, ≥300 = HIGH) | HIGH / MEDIUM |
| **SQL Injection** | SQLi patterns in URL paths (UNION, SLEEP, error-based, stacked queries) | CRITICAL / HIGH |
| **XSS Attempts** | XSS payloads in request paths/UA (script tags, event handlers, encoded) | HIGH |
| **Scanner Detection** | Known scanner UAs (Nikto, sqlmap, Nmap), path traversal, shell probes | HIGH / MEDIUM |
| **Suspicious User-Agent** | Empty, curl/wget, or scripted client UAs across multiple requests | LOW |

---

## Installation

```bash
git clone https://github.com/Babybluess/log-analyzer
cd log-analyzer
go build -o log-analyzer ./cmd/
```

---

## Usage

```bash
# Analyse nginx access log
./log-analyzer --nginx /var/log/nginx/access.log

# Analyse multiple log types together
./log-analyzer --nginx access.log --auth /var/log/auth.log --app app.log

# Custom session window (default: 10 minutes)
./log-analyzer --nginx access.log --window 5m

# Export findings to JSON and CSV
./log-analyzer --nginx access.log --json findings.json --csv findings.csv

# Show only HIGH and CRITICAL findings
./log-analyzer --nginx access.log --min-severity HIGH

# Test with sample data
./log-analyzer --nginx testdata/nginx_access.log --auth testdata/auth.log --app testdata/app.log
```

---

## Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  log-analyzer — IOC Analysis Report
  Scanned: 1842 log entries   Analysis time: 23ms
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Findings: CRITICAL=1  HIGH=3  MEDIUM=1  LOW=2

🔴 [CRITICAL] Brute-force attack from 45.33.32.156 (11 failed logins)
   Rule: AUTH_BRUTE_FORCE  |  IP: 45.33.32.156  |  Events: 11
   Period: 2026-09-08 10:05:01 → 10:05:11
   IP 45.33.32.156 made 11 failed authentication attempts in a 10s window.
   Targeted users: [root admin ubuntu pi git deploy ec2-user]
   Evidence:
     > Sep  8 10:05:01 server sshd[1234]: Failed password for root from 45.33.32.156
     ...

🟠 [HIGH] SQL injection attempts from 10.0.0.1 (3 requests)
   ...
```

---

## Log Format Support

### Nginx (combined log format)
```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes "$http_referer" "$http_user_agent"
```

### Linux Auth Log (`/var/log/auth.log`, `/var/log/secure`)
```
Sep  8 12:34:56 hostname sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2
```

### JSON Application Log (newline-delimited)
```json
{"timestamp":"2026-09-08T10:01:00Z","level":"warn","message":"Failed login","ip":"1.2.3.4","path":"/login","statusCode":401}
```
Supports field name variants from Winston, Pino, Zap, structlog, and custom formats.

---

## CI/CD Integration

```yaml
- name: Analyse access logs
  run: ./log-analyzer --nginx /var/log/nginx/access.log --min-severity HIGH
  # Exit code 2 = CRITICAL findings → fails pipeline
  # Exit code 1 = HIGH findings → fails pipeline
  # Exit code 0 = clean
```

---

## Architecture

```
cmd/main.go          ← CLI entry point (flags, orchestration)
internal/
  model/             ← Shared data types (LogEntry, IOC, Session)
  parser/
    nginx.go         ← Nginx combined log parser
    auth.go          ← Linux auth.log parser
    app.go           ← JSON application log parser (multi-format)
  correlator/        ← Groups entries into sessions by IP + time window
  detector/
    runner.go        ← Detector interface + RunAll orchestrator
    auth_bruteforce.go
    high_rate.go
    sqli.go
    xss.go
    scanner.go
    useragent.go
  reporter/          ← Terminal output, JSON export, CSV export
testdata/            ← Sample log files for testing
```

---

## Author

**Hoang Minh Thang** — [github.com/Babybluess](https://github.com/Babybluess)

⚠️ For authorised security analysis only. Only analyse logs from systems you own or have permission to inspect.
