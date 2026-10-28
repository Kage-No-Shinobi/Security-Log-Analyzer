import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer import analyze, parse_line, report_markdown
ROOT = Path(__file__).resolve().parents[1]

class LogTests(unittest.TestCase):
    def test_ssh_sample(self):
        summary = analyze((ROOT / 'samples/auth.log').read_text().splitlines())
        self.assertEqual(summary['failures']['192.0.2.10'], 5)
        self.assertTrue(any('within 5 minutes' in i['reason'] for i in summary['incidents']))
    def test_off_hours(self):
        incidents = analyze((ROOT / 'samples/auth.log').read_text().splitlines())['incidents']
        self.assertTrue(any('off-hours' in i['reason'] for i in incidents))
    def test_web_probe(self):
        summary = analyze((ROOT / 'samples/access.log').read_text().splitlines())
        self.assertTrue(any('sensitive path' in i['reason'] for i in summary['incidents']))
    def test_malformed_skipped(self):
        self.assertEqual(analyze(['not a log'])['skipped'], 1)
    def test_no_false_incident_on_one_failure(self):
        line = 'Oct 19 12:00:00 demo sshd[4]: Failed password for user x from 192.0.2.1 port 2 ssh2'
        self.assertFalse(analyze([line])['incidents'])
    def test_report_table(self):
        self.assertIn('| Severity |', report_markdown(analyze([]), 'sample.log'))

if __name__ == '__main__': unittest.main()
