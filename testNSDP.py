import NSDP
import unittest
import sys
import struct

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

class TestPacketBuilding(unittest.TestCase):
    def test_build_header(self):
        # test each allowed message type
        for msg_type in [ NSDP.NSDP_MSG_QUERY_REQUEST, 
                          NSDP.NSDP_MSG_QUERY_RESPONSE,
                          NSDP.NSDP_MSG_SET_REQUEST, 
                          NSDP.NSDP_MSG_SET_RESPONSE ]:
            query_req = struct.pack(">H", msg_type)
            header = NSDP._build_header(msg_type, b'abcdef', b'ghijkl', 0x5678)
            self.assertEqual(header, query_req + b'\x00' * 6 + 
                                     b'abcdefghijkl' + 
                                     b'\x00\x00\x56\x78NSDP' + b'\x00' * 4)
        # insure we don't allow other message types
        with self.assertRaises(AssertionError):
            NSDP._build_header(0x0000, b'abcdef', b'ghijkl', 0x5678)
        with self.assertRaises(AssertionError):
            NSDP._build_header(0x0001, b'abcdef', b'ghijkl', 0x5678)
        with self.assertRaises(AssertionError):
            NSDP._build_header(0x0401, b'abcdef', b'ghijkl', 0x5678)
        with self.assertRaises(AssertionError):
            NSDP._build_header(0xffff, b'abcdef', b'ghijkl', 0x5678)
        with self.assertRaises(AssertionError):
            NSDP._build_header(-1, b'abcdef', b'ghijkl', 0x5678)
        with self.assertRaises(AssertionError):
            NSDP._build_header('hello', b'abcdef', b'ghijkl', 0x5678)
        with self.assertRaises(AssertionError):
            NSDP._build_header([11,], b'abcdef', b'ghijkl', 0x5678)
        # verify we break on bogus MAC addresses
        msg_req = NSDP.NSDP_MSG_QUERY_REQUEST
        for bogus in [ 123, b'', b'x', b'y' * 7, b'z' * 500 ]:
            with self.assertRaises(AssertionError):
                NSDP._build_header(msg_req, bogus, b'ghijkl', 0x5678)
            with self.assertRaises(AssertionError):
                NSDP._build_header(msg_req, b'ghijkl', bogus, 0x5678)
            with self.assertRaises(AssertionError):
                NSDP._build_header(msg_req, bogus, bogus, 0x5678)
        # verify that our sequence number is checked
        msg_req = NSDP.NSDP_MSG_QUERY_REQUEST
        with self.assertRaises(AssertionError):
            NSDP._build_header(msg_type, b'abcdef', b'ghijkl', -1)
        with self.assertRaises(AssertionError):
            NSDP._build_header(msg_type, b'abcdef', b'ghijkl', 65536)
        with self.assertRaises(AssertionError):
            NSDP._build_header(msg_type, b'abcdef', b'ghijkl', 'xxx')
        # verify that we can use numbers in the allowed range
        for seq_num in [ 0, 1, 0xf, 0x10, 0xff, 0x100, 0xfff, 0x1000, 0xffff ]:
            packed_seq_num = struct.pack(">H", seq_num)
            header = NSDP._build_header(msg_type, b'abcdef', b'ghijkl', seq_num)
            self.assertEqual(header, query_req + b'\x00' * 6 + 
                                     b'abcdefghijkl\x00\x00' + packed_seq_num +
                                     b'NSDP' + b'\x00' * 4)

    def testQueryPacketData(self):
        # basic option type
        opt = NSDP._NSDPOption(1, 'name', 'desc')
        data = opt.build_query_packet_data()
        self.assertEqual(data, b'\x00\x01\x00\x00')
        # all options use the same code to build query

class TestOptionDefinition(unittest.TestCase):
    pass

class TestPacketParsing(unittest.TestCase):
    pass

class TestDiscoverNSDP(unittest.TestCase):
    pass

# TODO: test option id/name/desc

if __name__ == '__main__':
    unittest.main()
