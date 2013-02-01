import NSDP
import unittest
import sys

class TestMACFuncs(unittest.TestCase):
    def test_hw_ntop(self):
        # verify basic functionality
        mac_str = NSDP.hw_ntop(b"\x00" * 6)
        self.assertEqual(mac_str, "00:00:00:00:00:00")
        self.assertIsInstance(mac_str, str)
        mac_str = NSDP.hw_ntop(b"\x00\x01\x02\x03\x04\x05")
        self.assertEqual(mac_str, "00:01:02:03:04:05")
        self.assertIsInstance(mac_str, str)
        mac_str = NSDP.hw_ntop(b"\xff\xff\xff\xff\xff\xff")
        self.assertEqual(mac_str, "ff:ff:ff:ff:ff:ff")
        self.assertIsInstance(mac_str, str)
        # confirm our bounds checking
        with self.assertRaises(ValueError):
            mac_str = NSDP.hw_ntop(b"")
        with self.assertRaises(ValueError):
            mac_str = NSDP.hw_ntop(b"0")
        with self.assertRaises(ValueError):
            mac_str = NSDP.hw_ntop(b"1234567")
        with self.assertRaises(ValueError):
            mac_str = NSDP.hw_ntop(b"x" * 999)
        # verify behavior on invalid input type
        with self.assertRaises(TypeError):
            mac_str = NSDP.hw_ntop(123)
        # Input in Python 3 must be an array of bytes.
        if sys.version[0] == '3':
            with self.assertRaises(TypeError):
                mac_str = NSDP.hw_ntop("string")

if __name__ == '__main__':
    unittest.main()
