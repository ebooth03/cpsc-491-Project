import unittest
from scanner.network_scanner import NetworkScanner


class TestNetworkScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = NetworkScanner(timeout=1)

    def test_closed_port(self):
        result = self.scanner.scan_port("127.0.0.1", 1)

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()