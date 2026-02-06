# Pantheon Traffic Forensics

A small, focused toolkit for triaging traffic spikes using access logs. It ships with a CLI to summarize the noisiest
paths, IPs, user agents, and response codes plus a short runbook you can follow during incident response.

## Quick start

```bash
python -m ptf analyze sample/access.log --top 10
```

## CLI

```bash
python -m ptf analyze <logfile> --top 15 --json
```

Output includes:
- Top paths (normalized, query strings removed)
- Top IPs
- Top user agents
- Status code distribution
- Simple heuristics for suspicious traffic

## Runbook: 15-minute spike triage

1. Confirm the spike window and capture the log slice for that period.
2. Run the CLI to identify hot paths, agents, and IPs.
3. Validate the hot path:
   - Expected path (marketing campaign, cache warm, cron, API client)? Continue.
   - Unexpected path? Find the owner or roll back the change first.
4. Review top user agents:
   - Known browsers/clients? Probably legitimate.
   - Empty/unknown/bot-like? Treat as suspicious.
5. Review top IPs:
   - Known monitors/partners? Document an allowlist.
   - Unknown concentrated IPs? Rate limit or block.
6. Decide and act:
   - Block/limit at edge, or accept and document the spike.
7. Recheck after 30–60 minutes to confirm decay.

## Log format

The parser expects Nginx “combined” access logs:

```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```

If your format differs, adapt `src/ptf/parser.py`.

## Development

```bash
python scripts/lint.py
python -m unittest discover -s tests
```

## License

MIT
