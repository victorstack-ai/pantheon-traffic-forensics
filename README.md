# Pantheon Traffic Forensics

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)

A small, focused toolkit for triaging traffic spikes using access logs
on Pantheon hosting. It ships with a CLI to summarize the noisiest
paths, IPs, user agents, and response codes plus a short runbook you
can follow during incident response.

Supports both **Nginx** and **Apache** combined log formats.

---

## Installation

### From source

```bash
git clone https://github.com/victorstack-ai/pantheon-traffic-forensics.git
cd pantheon-traffic-forensics
pip install .
```

### With Docker

```bash
docker build -t ptf .
docker run --rm -v "$PWD/sample:/data" ptf analyze /data/access.log
```

---

## Quick start

```bash
# Analyze a log file (Nginx format, default)
python -m ptf analyze sample/access.log --top 10

# Analyze Apache combined logs
python -m ptf analyze /var/log/apache2/access.log --format apache

# Output as JSON for piping to jq or other tools
python -m ptf analyze sample/access.log --json

# Show top 20 results instead of the default 10
python -m ptf analyze sample/access.log --top 20

# Combine flags
python -m ptf analyze sample/access.log --format nginx --top 15 --json
```

---

## CLI reference

```
usage: ptf analyze [-h] [--top TOP] [--json] [--format {nginx,apache}] logfile

positional arguments:
  logfile               Path to access log

options:
  --top TOP             Top N results (default: 10)
  --json                JSON output
  --format {nginx,apache}
                        Log format: nginx or apache (default: nginx)
```

---

## Sample output

```
$ python -m ptf analyze sample/access.log --top 5

Total parsed requests: 5
Top paths:
  /pricing                       2
  /                              1
  /wp-json/wp/v2/posts           1
  /.env                          1
Top IPs:
  198.51.100.25                  2
  203.0.113.10                   2
  192.0.2.50                     1
Top user agents:
  Mozilla/5.0                    4
  curl/8.0                       1
Status codes:
  200: 4
  404: 1
Suspicious hits:
  bot-like-user-agent | /wp-json/wp/v2/posts | curl/8.0
  suspicious-path | /.env | Mozilla/5.0
```

---

## Log formats

### Nginx combined (default)

```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```

### Apache combined

```
%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
```

Both formats follow the same field order. The key difference is that
Apache may log `-` for a missing byte count while Nginx logs `0`.
The parser handles both transparently.

---

## Runbook: 15-minute spike triage

1. **Confirm the spike window** and capture the log slice for
   that period.
2. **Run the CLI** to identify hot paths, agents, and IPs.
3. **Validate the hot path:**
   - Expected path (marketing campaign, cache warm, cron, API
     client)? Continue.
   - Unexpected path? Find the owner or roll back the change
     first.
4. **Review top user agents:**
   - Known browsers/clients? Probably legitimate.
   - Empty/unknown/bot-like? Treat as suspicious.
5. **Review top IPs:**
   - Known monitors/partners? Document an allowlist.
   - Unknown concentrated IPs? Rate limit or block.
6. **Decide and act:**
   - Block/limit at edge, or accept and document the spike.
7. **Recheck** after 30-60 minutes to confirm decay.

---

## Development

```bash
# Run the linter
python scripts/lint.py

# Run tests
python -m unittest discover -s tests

# Run a single test file
python -m unittest tests.test_parser
```

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE)
for details.
