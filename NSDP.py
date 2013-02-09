"""
NSDP
====
This modules handles the proprietary protocol used to manage Netgear 
ProSafe switches. Some documentation is on the Wikipedia page:

  http://en.wikipedia.org/wiki/Netgear_NSDP

There are two classes:

  * DiscoverNSDP can be used to find ProSafe switches on the local
    network.

  * NSDP is used to query individual ProSafe switches, to set the
    configuration on them, or to execute actions (like reboot).

The general approach is to use DiscoverNSDP to find one or more
switches, and then to create a session for each by instantiating an 
NSDP object.
"""

import getifaddrs
import socket
import re
import binascii
import struct
import select

# get the best random number source possible
try:
    from ssl import RAND_bytes as rand_bytes
except ImportError:
    from os import urandom as rand_bytes

# exception hierarcy
class NSDPException(Exception): pass
class NSDPInterfaceNotFound(NSDPException): pass
class NSDPInterfaceNoMACAddress(NSDPException): pass
class NSDPInterfaceNoIPv4Address(NSDPException): pass
class NSDPBadPacket(NSDPException): pass
class NSDPPacketTooShort(NSDPBadPacket): pass

# well-known ports for communication
NSDP_RECV_PORT = 63321
NSDP_SEND_PORT = 63322

# message codes
NSDP_MSG_QUERY_REQUEST  = 0x0101
NSDP_MSG_QUERY_RESPONSE = 0x0102
NSDP_MSG_SET_REQUEST    = 0x0103
NSDP_MSG_SET_RESPONSE   = 0x0104

# TODO: possibly we should support 0-compression, 
#       like: 1:2:3:4:5:6 instead of 01:02:03:04:05:06
def hw_pton(mac):
    """Convert a printable MAC address into a binary format."""
    if not hasattr(mac, "strip"):
        raise TypeError()
    clean_mac = mac.strip().lower()
    mac_bytes = clean_mac.encode()
    if re.search(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', clean_mac):
        mac_bytes = mac_bytes[0:2] + mac_bytes[3:5] + mac_bytes[6:8] + \
                    mac_bytes[9:11] + mac_bytes[12:14] + mac_bytes[15:17]
    elif not re.search(r'^[0-9a-f]{12}$', clean_mac):
        raise ValueError("unknown format for MAC address: '%s'" % mac)
    return binascii.unhexlify(mac_bytes)

def hw_ntop(mac):
    """Convert a binary MAC address into a printable format.
    Input is a string in Python 2 or an array of bytes in Python 3."""
    if len(mac) != 6:
        raise ValueError("binary MAC addresses must be 6 bytes long")
    mac_bytes = binascii.hexlify(mac)
    mac_bytes = mac_bytes[0:2] + b':' + mac_bytes[2:4] + b':' + \
                mac_bytes[4:6] + b':' + mac_bytes[6:8] + b':' + \
                mac_bytes[8:10] + b':' + mac_bytes[10:12]
    return str(mac_bytes.decode())

def _build_header(msg_type, srcmac, dstmac, seq_num):
    """Make the header of NSDP packet"""
    assert(msg_type in [ NSDP_MSG_QUERY_REQUEST, NSDP_MSG_QUERY_RESPONSE,
                         NSDP_MSG_SET_REQUEST, NSDP_MSG_SET_RESPONSE ] )
    assert(type(srcmac) is bytes)
    assert(len(srcmac) == 6)
    assert(type(dstmac) is bytes)
    assert(len(dstmac) == 6)
    assert(type(seq_num) is int)
    assert((seq_num >= 0) and (seq_num <= 0xffff))
    header = struct.pack(">H", msg_type)
    header += b'\x00' * 6
    header += srcmac
    header += dstmac
    header += b'\x00' * 2
    header += struct.pack(">H", seq_num)
    header += b'NSDP' 
    header += b'\x00' * 4
    return header

class _NSDPOption:
    def __init__(self, option_id, option_name, option_desc):
        self.option_id = option_id
        self.option_name = option_name
        self.option_desc = option_desc
    def build_query_packet_data(self):
        data = struct.pack(">H", self.option_id)
        data += struct.pack(">H", 0)
        return data
    def build_set_packet_data(self):
        data = struct.pack(">H", self.option_id)
        data += struct.pack(">H", 0)
        return data
    def parse_reply(self, data):
        if len(data) != 0:
            raise NSDPBadPacket("unexpected data in option")
        return None

class _NSDPOptionString(_NSDPOption):
    def __init__(self, option_id, option_name, option_desc):
        _NSDPOption.__init__(self, option_id, option_name, option_desc)
    def build_set_packet_data(self, s):
        data = struct.pack(">H", self.option_id)
        data += struct.pack(">H", len(s))
        data += s.encode()
        return data
    def parse_reply(self, data):
        return str(data.decode())

class _NSDPOptionMAC(_NSDPOption):
    def __init__(self, option_id, option_name, option_desc):
        _NSDPOption.__init__(self, option_id, option_name, option_desc)
    def build_set_packet_data(self, mac):
        data = struct.pack(">H", self.option_id)
        data += struct.pack(">H", 6)
        data += hw_pton(mac)
        return data
    def parse_reply(self, data):
        if len(data) != 6:
            raise NSDPBadPacket("invalid MAC address")
        return hw_ntop(data)

class _NSDPOptionIPv4(_NSDPOption):
    def __init__(self, option_id, option_name, option_desc):
        _NSDPOption.__init__(self, option_id, option_name, option_desc)
    def build_set_packet_data(self, addr):
        data = struct.pack(">H", self.option_id)
        data += struct.pack(">H", 4)
        data += socket.inet_pton(socket.AF_INET, addr)
        return data
    def parse_reply(self, data):
        if len(data) != 4:
            raise NSDPBadPacket("invalid IPv4 address")
        return socket.inet_ntop(socket.AF_INET, data)

class _NSDPOptionBoolean(_NSDPOption):
    def __init__(self, option_id, option_name, option_desc):
        _NSDPOption.__init__(self, option_id, option_name, option_desc)
    def build_set_packet_data(self, boolean):
        data = struct.pack(">H", 1)
        if boolean:
            data += struct.pack(">b", 1)
        else:
            data += struct.pack(">b", 0)
        return data
    def parse_reply(self, data):
        if len(data) != 1:
            raise NSDPBadPacket("invalid boolean")
        if data[0] == 0:
            return False
        else:
            return True

class _NSDPOptionAction(_NSDPOption):
    def __init__(self, option_id, option_name, option_desc):
        _NSDPOption.__init__(self, option_id, option_name, option_desc)
    def build_set_packet_data(self):
        data = struct.pack(">H", 1)
        data += struct.pack(">b", 1)
        return data
    def parse_reply(self, data):
        raise NSDPBadPacket("unexpected action option received")

class _NSDPOptions:
    def __init__(self):
        self.options_by_id = { }
        self.options_by_name = { }
    def __getitem__(self, index):
        if index in self.options_by_id:
            return self.options_by_id[index]
        else:
            return self.options_by_name[index]
    def define(self, option_id, option_type, option_name, option_desc):
        if option_type == "empty":
            option_class = _NSDPOption
        elif option_type == "string":
            option_class = _NSDPOptionString
        elif option_type == "mac":
            option_class = _NSDPOptionMAC
        elif option_type == "ipv4":
            option_class = _NSDPOptionIPv4
        elif option_type == "bool":
            option_class = _NSDPOptionBoolean
        elif option_type == "action":
            option_class = _NSDPOptionAction
        else:
            raise NSDPException("unknown option type '%s'" % option_type)
        option = option_class(option_id, option_name, option_desc)
        self.options_by_id[option_id] = option
        self.options_by_name[option_name] = option
        return option

_options_data = [
    [ 0x0001, "string", "model",        "Model" ],
    [ 0x0003, "string", "name",         "Name"  ],
    [ 0x0004, "mac",    "mac",          "MAC"   ],
    [ 0x0006, "ipv4",   "ipv4addr",     "IPv4 address" ],
    [ 0x0007, "ipv4",   "ipv4netmask",  "IPv4 netmask" ],
    [ 0x0008, "ipv4",   "ipv4gateway",  "IPv4 gateway" ],
    [ 0x0009, "string", "new_password", "New password" ],
    [ 0x000a, "string", "password",     "Password" ],
    [ 0x000B, "bool",   "use_dhcp",     "Use DHCP?" ],
    [ 0x000D, "string", "firmware_ver", "Firmware version" ],
    [ 0x0013, "action", "reboot",       "Reboot" ],
    [ 0xFFFF, "empty",   "end",         "End of options marker" ],
]
nsdp_options = _NSDPOptions()
for option in _options_data:
    nsdp_options.define(option[0], option[1], option[2], option[3])

def _parse_packet(packet):
    if len(packet) < 24:
        raise NSDPPacketTooShort()
    parsed = { }
    # parse the header fields
    parsed["msg_type"] = struct.unpack(">H", packet[0:2])[0]
    parsed["result_code"] = struct.unpack(">H", packet[2:4])[0]
    parsed["error_code"] = struct.unpack(">H", packet[4:6])[0]
    # packet[6:8] unknown
    parsed["client_mac"] = hw_ntop(packet[8:14])
    parsed["server_mac"] = hw_ntop(packet[14:20])
    # packet[20:22] unknown
    parsed["seq_num"] = struct.unpack(">H", packet[22:24])[0]
    parsed["protocol"] = str(packet[24:28].decode())
    # packet[28:32] unknown
    options = { }
    pos = 32
    while pos < len(packet):
        if len(packet) - pos < 4:
            raise NSDPBadPacket("Truncated packet")
        option_id = struct.unpack(">H", packet[pos:pos+2])[0]
        option_len = struct.unpack(">H", packet[pos+2:pos+4])[0]
        pos = pos + 4
        if len(packet) - pos < option_len:
            raise NSDPBadPacket("Truncated packet")
        option_data = packet[pos:pos+option_len]
        opt = nsdp_options[option_id]
        # TODO: check for option that appears more than once
        options[opt.option_name] = opt.parse_reply(option_data)
        pos = pos + option_len
    parsed["options"] = options
    return parsed

class DiscoverNSDP:
    def _setup(self, iface_info):
        """
        """
        # make sure that we have both a MAC (hardware) address and 
        # an IPv4 address for this interface
        # note: if we have multiple hardware or IPv4 addresses we will
        #       just use the first one 
        if not 'hw' in iface_info:
            raise NSDPInterfaceNoMACAddress()
        if not 'ipv4' in iface_info:
            raise NSDPInterfaceNoIPv4Address()
        self.mac = iface_info['hw'][0]['addr']
        self.ip = iface_info['ipv4'][0]['addr']

        self.src_mac_bin = hw_pton(self.mac)
        self.dst_mac_bin = hw_pton('00:00:00:00:00:00')
        
        # we need to bind to the address on the interface to insure
        # that we send from the correct interface
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.send_sock.bind((self.ip, NSDP_RECV_PORT))

        # we also need to bind to the broadcast address to receive 
        # broadcast packets, apparently
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.recv_sock.bind(('255.255.255.255', NSDP_RECV_PORT))

        self.seq_num = None

    def __init__(self, interface_name): 
        """
        """
        ifaddrs = getifaddrs.getifaddrs()
        if not interface_name in ifaddrs:
            raise NSDPInterfaceNotFound()
        self._setup(ifaddrs[interface_name])

    def send(self):
        self.seq_num = struct.unpack("H", rand_bytes(2))[0]
        packet = _build_header(NSDP_MSG_QUERY_REQUEST, 
                               self.src_mac_bin, self.dst_mac_bin, self.seq_num)
        options = [ "model", "name", "mac", "ipv4addr", "firmware_ver" ]
        for option in options:
            packet += nsdp_options[option].build_query_packet_data()
        packet += nsdp_options["end"].build_query_packet_data()
        self.send_sock.sendto(packet, ('255.255.255.255', NSDP_SEND_PORT))

    def recv(self):
        # loop here chucking out packets that are not for us...
        # bad seq_num, msg_type, ...?
        (rlist, wlist, xlist) = select.select([self.recv_sock], [], [], 0)
        if self.recv_sock in rlist:
            (data, srcaddr) = self.recv_sock.recvfrom(8192)
            return _parse_packet(data)
        else:
            return None

class NSDP:
    pass

