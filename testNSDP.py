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

    def test_hw_pton(self):
        # verify basic functionality
        mac = NSDP.hw_pton("00:00:00:00:00:00")
        self.assertEqual(mac, b'\x00\x00\x00\x00\x00\x00')
        self.assertIsInstance(mac, bytes)
        mac = NSDP.hw_pton("10:0f:0e:0d:0c:0b")
        self.assertEqual(mac, b'\x10\x0f\x0e\x0d\x0c\x0b')
        self.assertIsInstance(mac, bytes)
        mac = NSDP.hw_pton("ff:ff:ff:ff:ff:ff")
        self.assertEqual(mac, b'\xff\xff\xff\xff\xff\xff')
        self.assertIsInstance(mac, bytes)
        # confirm that we are case-insensitive
        mac = NSDP.hw_pton("AB:cD:ef:FE:dC:ba")
        self.assertEqual(mac, b'\xab\xcd\xef\xfe\xdc\xba')
        self.assertIsInstance(mac, bytes)
        # check whitespace handling
        mac = NSDP.hw_pton(" 01:23:45:67:89:ab")
        self.assertEqual(mac, b'\x01\x23\x45\x67\x89\xab')
        self.assertIsInstance(mac, bytes)
        mac = NSDP.hw_pton(" " * 50 + "01:23:45:67:89:ab")
        self.assertEqual(mac, b'\x01\x23\x45\x67\x89\xab')
        self.assertIsInstance(mac, bytes)
        mac = NSDP.hw_pton("01:23:45:67:89:ab\t")
        self.assertEqual(mac, b'\x01\x23\x45\x67\x89\xab')
        self.assertIsInstance(mac, bytes)
        mac = NSDP.hw_pton("01:23:45:67:89:ab" + "\t" * 127)
        self.assertEqual(mac, b'\x01\x23\x45\x67\x89\xab')
        self.assertIsInstance(mac, bytes)
        with self.assertRaises(ValueError):
            mac = NSDP.hw_pton("01:23:45: 67:89:ab")
        with self.assertRaises(ValueError):
            mac = NSDP.hw_pton("0\t1:23:45:67:89:ab")
        # verify behavior on invalid input type
        with self.assertRaises(TypeError):
            mac_str = NSDP.hw_pton(123)
        # check various badly-formatted strings
        with self.assertRaises(ValueError):
            mac_str = NSDP.hw_pton("hello, MAC address")
        with self.assertRaises(ValueError):
            mac_str = NSDP.hw_pton("00:00:00:00:00:0")
        with self.assertRaises(ValueError):
            mac_str = NSDP.hw_pton("00:00:00:00:0000")
            
if __name__ == '__main__':
    unittest.main()
