import unittest
from unittest.mock import patch

from scanner import PortScanner, ScanResult


class TestPortScannerTargets(unittest.TestCase):
    def test_scan_target_hostname_resolution(self):
        scanner = PortScanner(max_workers=1)

        with patch('scanner.socket.gethostbyname_ex', return_value=('example.com', [], ['93.184.216.34'])), \
             patch.object(PortScanner, 'scan_port', return_value=ScanResult('93.184.216.34', 80, 'http')) as mock_scan:
            results = scanner.scan_target(['example.com'], [80], show_progress=False)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].ip, '93.184.216.34')
        mock_scan.assert_called_once_with(('93.184.216.34', 80), False)

    def test_scan_target_invalid_target_returns_empty_results(self):
        scanner = PortScanner(max_workers=1)

        with patch('scanner.console.print') as mock_print:
            results = scanner.scan_target(['bad target'], [80], show_progress=False)

        self.assertEqual(results, [])
        mock_print.assert_called()


if __name__ == '__main__':
    unittest.main()
