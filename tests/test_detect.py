"""Unit tests for the detection rules. Run: python3 -m unittest discover -s tests"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "detections"))

import detect  # noqa: E402


class DetectRulesTest(unittest.TestCase):
    def setUp(self):
        events = detect.load_events_file(os.path.join(HERE, "sample_events.json"))
        self.findings = detect.evaluate(events, detect.DEFAULT_SECRET_ALLOWLIST)
        self.by_rule = {}
        for f in self.findings:
            self.by_rule.setdefault(f.rule_id, []).append(f)

    def test_policy_version_escalation(self):
        hits = self.by_rule["LAB-001"]
        self.assertEqual(len(hits), 2)  # one succeeded, one blocked attempt
        self.assertTrue(any("attempt failed" in h.detail for h in hits))

    def test_admin_attach_from_cloudtrail_event_wrapper(self):
        self.assertEqual(len(self.by_rule["LAB-002"]), 1)

    def test_log_tampering(self):
        hit = self.by_rule["LAB-003"][0]
        self.assertEqual(hit.principal, "lab-ops")
        self.assertEqual(hit.severity, "CRITICAL")

    def test_secret_allowlist(self):
        hits = self.by_rule["LAB-004"]
        self.assertEqual(len(hits), 1)  # own secret and root access are not findings
        self.assertIn("lab/prod/db-credentials", hits[0].detail)

    def test_secret_enumeration(self):
        principals = {h.principal for h in self.by_rule["LAB-005"]}
        self.assertEqual(principals, {"lab-app", "lab-intern"})

    def test_denied_burst(self):
        hit = self.by_rule["LAB-006"][0]
        self.assertEqual(hit.principal, "lab-intern")
        self.assertIn("3 denied calls", hit.detail)

    def test_successful_only_drops_failed_attempts(self):
        events = detect.load_events_file(os.path.join(HERE, "sample_events.json"))
        findings = detect.evaluate(events, detect.DEFAULT_SECRET_ALLOWLIST, include_failed=False)
        self.assertFalse(any("attempt failed" in f.detail for f in findings))


if __name__ == "__main__":
    unittest.main()
