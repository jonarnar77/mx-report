import os
import unittest

MODULE_PATH = os.path.join(os.path.dirname(__file__), '..', 'mx-report.py')


def load_calculate_health_summary(path: str):
    """Dynamically load the `calculate_health_summary` function from the
    mx-report script without importing the entire file (which contains
    syntax errors in other sections)."""
    with open(path, 'r') as f:
        source = f.read()
    start = source.index('def _has_valid_dkim')
    end = source.index('def print_report_text')
    snippet = source[start:end]
    namespace = {}
    exec(snippet, namespace)
    return namespace['calculate_health_summary']


calculate_health_summary = load_calculate_health_summary(MODULE_PATH)

class TestCalculateHealthSummary(unittest.TestCase):
    def test_health_good(self):
        mx_info = {
            'records': [{'preference': 10, 'exchange': 'mx.example.com'}],
            'provider': 'Other',
            'warnings': []
        }
        spf_info = {
            'record': 'v=spf1 ~all',
            'warnings': [],
            'recommendations': [],
            'parsed_components': [
                {'raw': 'v=spf1', 'type': 'version', 'value': 'spf1', 'qualifier': ''},
                {'raw': '~all', 'type': 'all', 'value': '', 'qualifier': '~'}
            ]
        }
        dmarc_info = {
            'record': 'v=DMARC1; p=reject',
            'warnings': [],
            'recommendations': [],
            'parsed': {'p': 'reject'}
        }
        dkim_info = {
            'selectors_checked': [
                {'selector': 'test', 'found': True, 'record': 'v=DKIM1; p=abc', 'error': None}
            ],
            'warnings': [],
            'recommendations': []
        }
        summary = calculate_health_summary('example.com', mx_info, spf_info, dmarc_info, dkim_info)
        self.assertEqual(summary['status'], 'GOOD')
        self.assertEqual(summary['issues_count'], 0)
        self.assertEqual(summary['score'], 4)

    def test_health_missing_spf_and_dmarc(self):
        mx_info = {
            'records': [{'preference': 10, 'exchange': 'mx.example.com'}],
            'provider': 'Other',
            'warnings': []
        }
        spf_info = {
            'record': None,
            'warnings': [],
            'recommendations': [],
            'parsed_components': []
        }
        dmarc_info = {
            'record': None,
            'warnings': [],
            'recommendations': [],
            'parsed': {}
        }
        dkim_info = {
            'selectors_checked': [],
            'warnings': [],
            'recommendations': []
        }
        summary = calculate_health_summary('example.com', mx_info, spf_info, dmarc_info, dkim_info)
        self.assertEqual(summary['status'], 'NEEDS ATTENTION')
        self.assertGreaterEqual(summary['issues_count'], 2)
        self.assertTrue(any(d.startswith('- Important: SPF record is missing.') for d in summary['details']))
        self.assertTrue(any(d.startswith('- Important: DMARC record is missing.') for d in summary['details']))

    def test_health_dmarc_monitoring(self):
        mx_info = {
            'records': [{'preference': 10, 'exchange': 'mx.example.com'}],
            'provider': 'Other',
            'warnings': []
        }
        spf_info = {
            'record': 'v=spf1 -all',
            'warnings': [],
            'recommendations': [],
            'parsed_components': [
                {'raw': 'v=spf1', 'type': 'version', 'value': 'spf1', 'qualifier': ''},
                {'raw': '-all', 'type': 'all', 'value': '', 'qualifier': '-'}
            ]
        }
        dmarc_info = {
            'record': 'v=DMARC1; p=none; rua=mailto:admin@example.com',
            'warnings': [],
            'recommendations': [],
            'parsed': {'p': 'none', 'rua': 'mailto:admin@example.com'}
        }
        dkim_info = {
            'selectors_checked': [],
            'warnings': [],
            'recommendations': []
        }
        summary = calculate_health_summary('example.com', mx_info, spf_info, dmarc_info, dkim_info)
        self.assertEqual(summary['status'], 'FAIR')
        self.assertEqual(summary['issues_count'], 0)
        self.assertAlmostEqual(summary['score'], 2.5)

if __name__ == '__main__':
    unittest.main()
