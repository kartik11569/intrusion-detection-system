import unittest
from pathlib import Path

from ids_engine import analyze_file, parse_log_lines


class IdsEngineTests(unittest.TestCase):
    def test_sample_log_raises_expected_alerts(self):
        result = analyze_file(Path("samples/sample_mixed.log"), Path("data/blocklist.txt"))
        rules = {alert["rule"] for alert in result["alerts"]}

        self.assertEqual(result["summary"]["events_analyzed"], 28)
        self.assertIn("Repeated failed login attempts", rules)
        self.assertIn("Possible port scan", rules)
        self.assertIn("SQL injection probe", rules)
        self.assertIn("Cross-site scripting probe", rules)
        self.assertIn("Path traversal probe", rules)
        self.assertIn("Known suspicious indicator", rules)

    def test_parser_extracts_firewall_fields(self):
        events = parse_log_lines(
            ["2026-05-09T18:11:01 src=10.0.0.9 dst=10.0.0.2 dpt=22 action=DENY proto=TCP"]
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].src_ip, "10.0.0.9")
        self.assertEqual(events[0].dst_ip, "10.0.0.2")
        self.assertEqual(events[0].dst_port, 22)
        self.assertEqual(events[0].event_type, "network_connection")

    def test_parser_extracts_web_request(self):
        events = parse_log_lines(
            [
                '10.0.0.5 - - [09/May/2026:18:10:03 +0530] "GET /login?id=1 HTTP/1.1" 200 512'
            ]
        )

        self.assertEqual(events[0].src_ip, "10.0.0.5")
        self.assertEqual(events[0].fields["method"], "GET")
        self.assertEqual(events[0].fields["path"], "/login?id=1")
        self.assertEqual(events[0].event_type, "web_request")


if __name__ == "__main__":
    unittest.main()
