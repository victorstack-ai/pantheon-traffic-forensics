import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from ptf.parser import parse_line, summarize  # noqa: E402


class TestParser(unittest.TestCase):
    def test_parse_line(self):
        line = (
            '203.0.113.10 - - [06/Feb/2026:10:12:01 +0000] '
            '"GET /pricing?utm=ad HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        )
        event = parse_line(line)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.ip, "203.0.113.10")
        self.assertEqual(event.path, "/pricing")
        self.assertEqual(event.status, 200)

    def test_summarize_counts(self):
        lines = [
            '203.0.113.10 - - [06/Feb/2026:10:12:01 +0000] '
            '"GET / HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
            '203.0.113.10 - - [06/Feb/2026:10:12:02 +0000] '
            '"GET /wp-json/wp/v2/posts HTTP/1.1" 200 1024 "-" "curl/8.0"',
        ]
        summary = summarize(lines, top=5)
        self.assertEqual(summary.total, 2)
        self.assertEqual(summary.top_paths[0][0], "/")
        self.assertEqual(summary.top_ips[0][0], "203.0.113.10")
        self.assertEqual(summary.status_counts, [(200, 2)])
        self.assertTrue(summary.suspicious_hits)


if __name__ == "__main__":
    unittest.main()
