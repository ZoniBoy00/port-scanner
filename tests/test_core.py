import unittest
from unittest.mock import patch

from core import run_scan


class TestRunScan(unittest.TestCase):
    def test_run_scan_with_empty_ports_prints_error(self):
        with patch('core.console.print') as mock_print:
            run_scan(
                targets=['127.0.0.1'],
                ports=[],
                timeout=0.1,
                workers=1,
                banner=False,
                verbose=False,
                no_progress=True,
                output=None,
            )

        mock_print.assert_called_once_with('[red]Error[/red] No valid ports specified.')


if __name__ == '__main__':
    unittest.main()
