import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import security_tool as tool

NOW = datetime(2026, 10, 13, 12, tzinfo=timezone.utc)


class ReportingTests(unittest.TestCase):
    def test_demo_generates_explainable_findings(self):
        results = tool.audit(copy.deepcopy(tool.DEMO), {}, NOW)
        self.assertTrue(results)
        self.assertTrue(all(item['remediation'] and item['evidence'] for item in results))

    def test_fingerprints_are_deterministic(self):
        self.assertEqual(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW),
                         tool.audit(copy.deepcopy(tool.DEMO), {}, NOW))

    def test_active_and_expired_suppressions(self):
        rows = tool.audit(copy.deepcopy(tool.DEMO), {}, NOW)
        item = {'fingerprint': rows[0]['fingerprint'], 'reason': 'Synthetic exception review',
                'expires': '2027-01-01T00:00:00Z'}
        self.assertEqual(len(tool.build_report(rows, [item], NOW)['suppressed']), 1)
        item['expires'] = '2026-01-01T00:00:00Z'
        self.assertEqual(len(tool.build_report(rows, [item], NOW)['suppressed']), 0)

    def test_invalid_exception_and_input(self):
        with self.assertRaises(ValueError):
            tool.build_report([], [{'fingerprint': 'x', 'reason': '', 'expires': 'bad'}], NOW)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            tool.audit({}, {}, NOW)
        duplicate = {'fingerprint': 'same', 'reason': 'Synthetic test exception', 'expires': '2027-01-01T00:00:00Z'}
        with self.assertRaises(ValueError):
            tool.build_report([], [duplicate, duplicate], NOW)

    def test_json_ambiguity_rejected(self):
        for content in ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}']:
            with self.assertRaises(ValueError):
                tool.decode_json(content)

    def test_sarif_contains_rules_and_stable_fingerprints(self):
        report = tool.build_report(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW), now=NOW)
        result = tool.sarif(report)
        self.assertEqual(result['version'], '2.1.0')
        self.assertEqual(len(result['runs'][0]['results']), len(report['findings']))
        self.assertTrue(all(x['partialFingerprints'] for x in result['runs'][0]['results']))

    def test_cli_demo_and_missing_input(self):
        script = Path(__file__).with_name('security_tool.py')
        result = subprocess.run([sys.executable, str(script), '--demo', '--now', NOW.isoformat()],
                                capture_output=True, text=True)
        self.assertIn(result.returncode, [0, 1], result.stderr)
        self.assertEqual(json.loads(result.stdout)['tool'], tool.TOOL)
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)

from unittest.mock import patch


class TLSTests(unittest.TestCase):
    def test_wildcard_is_one_label_only(self):
        self.assertTrue(tool.host_covered('api.example.com', ['*.example.com'], []))
        self.assertFalse(tool.host_covered('a.b.example.com', ['*.example.com'], []))
        self.assertFalse(tool.host_covered('example.com', ['*.example.com'], []))

    def test_ip_sans_are_separate(self):
        self.assertFalse(tool.host_covered('192.0.2.10', ['192.0.2.10'], []))
        self.assertTrue(tool.host_covered('192.0.2.10', [], ['192.0.2.10']))

    def test_clean_certificate(self):
        data = copy.deepcopy(tool.DEMO)
        data['certificates'][0].update(not_after='2027-01-01T00:00:00Z', dns_sans=['portal.example'], protocol='TLSv1.3', verified_chain=True, cipher_bits=256)
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_expired_certificate_is_critical(self):
        self.assertEqual(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW)[0]['severity'], 'critical')

    def test_connection_failures_are_findings(self):
        with patch.object(tool, 'capture_tls', side_effect=OSError('unavailable')):
            result = tool.audit({'targets': [{'hostname': 'portal.example'}]}, {}, NOW)
        self.assertEqual(result[0]['rule'], 'TLS-HANDSHAKE-FAILED')

    def test_invalid_policy_and_target(self):
        with self.assertRaises(ValueError):
            tool.audit(copy.deepcopy(tool.DEMO), {'urgent_days': 60}, NOW)
        with self.assertRaises(ValueError):
            tool.capture_tls('https://example.com')


if __name__ == "__main__":
    unittest.main()
