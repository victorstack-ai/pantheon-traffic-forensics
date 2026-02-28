import sys
import unittest
from pathlib import Path

sys.path.append(
    str(Path(__file__).resolve().parents[1] / "src")
)

from ptf.parser import (  # noqa: E402
    LogEvent,
    classify_suspicious,
    normalize_path,
    parse_line,
    summarize,
)


class TestNormalizePath(unittest.TestCase):
    def test_strips_query_string(self):
        self.assertEqual(
            normalize_path("/page?foo=1"), "/page"
        )

    def test_no_query_string(self):
        self.assertEqual(normalize_path("/page"), "/page")

    def test_multiple_question_marks(self):
        self.assertEqual(
            normalize_path("/p?a=1?b=2"), "/p"
        )


class TestParseLineNginx(unittest.TestCase):
    def test_basic_nginx_line(self):
        line = (
            '203.0.113.10 - - [06/Feb/2026:10:12:01 +0000]'
            ' "GET /pricing?utm=ad HTTP/1.1" 200 512'
            ' "-" "Mozilla/5.0"'
        )
        event = parse_line(line, fmt="nginx")
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.ip, "203.0.113.10")
        self.assertEqual(event.path, "/pricing")
        self.assertEqual(event.status, 200)
        self.assertEqual(event.agent, "Mozilla/5.0")

    def test_malformed_line_returns_none(self):
        self.assertIsNone(parse_line("not a log line"))

    def test_empty_line_returns_none(self):
        self.assertIsNone(parse_line(""))

    def test_partial_line_returns_none(self):
        line = '203.0.113.10 - - [06/Feb/2026:10:12:01 +0000]'
        self.assertIsNone(parse_line(line))

    def test_ipv6_address(self):
        line = (
            '2001:db8::1 - - [06/Feb/2026:10:12:01 +0000]'
            ' "GET /home HTTP/1.1" 200 1024'
            ' "-" "Mozilla/5.0"'
        )
        event = parse_line(line, fmt="nginx")
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.ip, "2001:db8::1")
        self.assertEqual(event.path, "/home")

    def test_missing_user_agent_field(self):
        # User agent is empty string
        line = (
            '10.0.0.1 - - [06/Feb/2026:10:12:01 +0000]'
            ' "GET /api HTTP/1.1" 200 256'
            ' "-" ""'
        )
        event = parse_line(line, fmt="nginx")
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.agent, "")

    def test_post_method(self):
        line = (
            '192.168.1.1 - admin'
            ' [06/Feb/2026:10:12:01 +0000]'
            ' "POST /login HTTP/1.1" 302 0'
            ' "https://example.com" "Mozilla/5.0"'
        )
        event = parse_line(line, fmt="nginx")
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.method, "POST")
        self.assertEqual(event.path, "/login")
        self.assertEqual(event.status, 302)

    def test_large_status_code(self):
        line = (
            '10.0.0.1 - - [06/Feb/2026:10:12:01 +0000]'
            ' "GET / HTTP/1.1" 503 0'
            ' "-" "Mozilla/5.0"'
        )
        event = parse_line(line, fmt="nginx")
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.status, 503)

    def test_whitespace_padding_stripped(self):
        line = (
            '  203.0.113.10 - -'
            ' [06/Feb/2026:10:12:01 +0000]'
            ' "GET / HTTP/1.1" 200 100'
            ' "-" "Mozilla/5.0"  '
        )
        event = parse_line(line, fmt="nginx")
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.ip, "203.0.113.10")


class TestParseLineApache(unittest.TestCase):
    def test_basic_apache_line(self):
        line = (
            '198.51.100.25 - frank'
            ' [10/Oct/2025:13:55:36 -0700]'
            ' "GET /index.html HTTP/1.0" 200 2326'
            ' "http://www.example.com/start.html"'
            ' "Mozilla/4.08"'
        )
        event = parse_line(line, fmt="apache")
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.ip, "198.51.100.25")
        self.assertEqual(event.path, "/index.html")
        self.assertEqual(event.status, 200)
        self.assertEqual(event.agent, "Mozilla/4.08")

    def test_apache_dash_bytes(self):
        # Apache may log "-" when no bytes are sent
        line = (
            '10.0.0.5 - - [10/Oct/2025:13:55:36 -0700]'
            ' "HEAD /health HTTP/1.1" 204 -'
            ' "-" "HealthCheck/1.0"'
        )
        event = parse_line(line, fmt="apache")
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.status, 204)

    def test_apache_ipv6(self):
        line = (
            '::1 - - [10/Oct/2025:13:55:36 -0700]'
            ' "GET /status HTTP/1.1" 200 128'
            ' "-" "curl/7.68.0"'
        )
        event = parse_line(line, fmt="apache")
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.ip, "::1")

    def test_apache_malformed_returns_none(self):
        self.assertIsNone(
            parse_line("garbage data", fmt="apache")
        )

    def test_apache_empty_agent(self):
        line = (
            '10.0.0.1 - - [10/Oct/2025:13:55:36 -0700]'
            ' "GET /robots.txt HTTP/1.1" 200 42'
            ' "-" ""'
        )
        event = parse_line(line, fmt="apache")
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.agent, "")


class TestInvalidFormat(unittest.TestCase):
    def test_unknown_format_raises(self):
        with self.assertRaises(ValueError):
            parse_line("anything", fmt="iis")


class TestClassifySuspicious(unittest.TestCase):
    def test_empty_agent(self):
        event = LogEvent(
            ip="1.2.3.4",
            method="GET",
            path="/",
            status=200,
            agent="",
        )
        self.assertEqual(
            classify_suspicious(event), "empty-user-agent"
        )

    def test_bot_agent(self):
        event = LogEvent(
            ip="1.2.3.4",
            method="GET",
            path="/",
            status=200,
            agent="Googlebot/2.1",
        )
        self.assertEqual(
            classify_suspicious(event),
            "bot-like-user-agent",
        )

    def test_suspicious_path(self):
        event = LogEvent(
            ip="1.2.3.4",
            method="GET",
            path="/.env",
            status=404,
            agent="Mozilla/5.0",
        )
        self.assertEqual(
            classify_suspicious(event), "suspicious-path"
        )

    def test_normal_request(self):
        event = LogEvent(
            ip="1.2.3.4",
            method="GET",
            path="/about",
            status=200,
            agent="Mozilla/5.0",
        )
        self.assertIsNone(classify_suspicious(event))


class TestSummarize(unittest.TestCase):
    def test_nginx_summarize_counts(self):
        lines = [
            '203.0.113.10 - -'
            ' [06/Feb/2026:10:12:01 +0000]'
            ' "GET / HTTP/1.1" 200 2048'
            ' "-" "Mozilla/5.0"',
            '203.0.113.10 - -'
            ' [06/Feb/2026:10:12:02 +0000]'
            ' "GET /wp-json/wp/v2/posts HTTP/1.1"'
            ' 200 1024 "-" "curl/8.0"',
        ]
        summary = summarize(lines, top=5, fmt="nginx")
        self.assertEqual(summary.total, 2)
        self.assertEqual(summary.top_paths[0][0], "/")
        self.assertEqual(
            summary.top_ips[0][0], "203.0.113.10"
        )
        self.assertEqual(summary.status_counts, [(200, 2)])
        self.assertTrue(summary.suspicious_hits)

    def test_apache_summarize(self):
        lines = [
            '10.0.0.1 - - [10/Oct/2025:13:55:36 -0700]'
            ' "GET /page1 HTTP/1.1" 200 512'
            ' "-" "Mozilla/5.0"',
            '10.0.0.2 - - [10/Oct/2025:13:55:37 -0700]'
            ' "GET /page1 HTTP/1.1" 200 512'
            ' "-" "Mozilla/5.0"',
            '10.0.0.1 - - [10/Oct/2025:13:55:38 -0700]'
            ' "GET /page2 HTTP/1.1" 404 0'
            ' "-" "Mozilla/5.0"',
        ]
        summary = summarize(lines, top=5, fmt="apache")
        self.assertEqual(summary.total, 3)
        self.assertEqual(summary.top_paths[0], ("/page1", 2))
        self.assertEqual(
            summary.status_counts, [(200, 2), (404, 1)]
        )

    def test_summarize_skips_malformed(self):
        lines = [
            "not a valid line",
            '203.0.113.10 - -'
            ' [06/Feb/2026:10:12:01 +0000]'
            ' "GET / HTTP/1.1" 200 2048'
            ' "-" "Mozilla/5.0"',
            "",
        ]
        summary = summarize(lines, top=5)
        self.assertEqual(summary.total, 1)

    def test_summarize_empty_input(self):
        summary = summarize([], top=5)
        self.assertEqual(summary.total, 0)
        self.assertEqual(summary.top_paths, [])
        self.assertEqual(summary.top_ips, [])

    def test_top_limits_results(self):
        lines = [
            f'10.0.0.{i} - -'
            f' [06/Feb/2026:10:12:0{i} +0000]'
            f' "GET /p{i} HTTP/1.1" 200 100'
            f' "-" "Agent{i}"'
            for i in range(1, 6)
        ]
        summary = summarize(lines, top=2)
        self.assertLessEqual(len(summary.top_paths), 2)
        self.assertLessEqual(len(summary.top_ips), 2)


if __name__ == "__main__":
    unittest.main()
