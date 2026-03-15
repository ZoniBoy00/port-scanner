import unittest

from utils import COMMON_PORTS, parse_port_range


class TestParsePortRange(unittest.TestCase):
    def test_common_keyword(self):
        self.assertEqual(parse_port_range('common'), COMMON_PORTS)

    def test_all_keyword(self):
        ports = parse_port_range('all')
        self.assertEqual(ports[0], 1)
        self.assertEqual(ports[-1], 65535)
        self.assertEqual(len(ports), 65535)

    def test_invalid_values_are_ignored(self):
        ports = parse_port_range('80,0,65536,abc,100-90,443')
        self.assertEqual(ports, [80, 443])


if __name__ == '__main__':
    unittest.main()
