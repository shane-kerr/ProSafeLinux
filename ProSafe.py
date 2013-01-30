"""
ProSafe
=======
This class handles the proprietary protocol used to manage Netgear 
ProSafe switches. Some documentation is on the Wikipedia page:

  http://en.wikipedia.org/wiki/Netgear_NSDP

There are two classes:

  * ProSafeDiscover can be used to find ProSafe switches on the local
    network.

  * ProSafe is used to query individual ProSafe switches, or to set
    the configuration on them.
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
class ProSafeException(Exception): pass
class ProSafeInterfaceNotFound(ProSafeException): pass
class ProSafeInterfaceNoMACAddress(ProSafeException): pass
class ProSafeInterfaceNoIPv4Address(ProSafeException): pass
class ProSafeBadPacket(ProSafeException): pass
class ProSafePacketTooShort(ProSafeBadPacket): pass

# well-known ports for communication
PROSAFE_RECV_PORT = 63321
PROSAFE_SEND_PORT = 63322

# message codes
PROSAFE_MSG_QUERY_REQUEST  = 0x0101
PROSAFE_MSG_QUERY_RESPONSE = 0x0102
PROSAFE_MSG_SET_REQUEST    = 0x0103
PROSAFE_MSG_SET_RESPONSE   = 0x0104

def hw_pton(mac):
    clean_mac = mac.strip().lower()
    mac_bytes = clean_mac.encode()
    if re.search(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', clean_mac):
        mac_bytes = mac_bytes[0:2] + mac_bytes[3:5] + mac_bytes[6:8] + \
                    mac_bytes[9:11] + mac_bytes[12:14] + mac_bytes[15:17]
    elif not re.search(r'^[0-9a-f]{12}$', clean_mac):
        raise ValueError("unknown format for MAC address: '%s'" % mac)
    return binascii.unhexlify(mac_bytes)

def hw_ntop(mac):
    # XXX: check type? at least document... byte[] / str /...
    #if len(mac) != 6:
    #    raise XXX
    mac_bytes = binascii.hexlify(mac)
    mac_bytes = mac_bytes[0:2] + b':' + mac_bytes[2:4] + b':' + \
                mac_bytes[4:6] + b':' + mac_bytes[6:8] + b':' + \
                mac_bytes[8:10] + b':' + mac_bytes[10:12]
    return mac_bytes.decode()

def _build_header(msg_type, srcmac, dstmac, seq_num):
    header = struct.pack(">h", msg_type)
    header += b'\x00' * 6
    header += srcmac
    header += dstmac
    header += b'\x00' * 2
    header += struct.pack(">h", seq_num)
    header += b'NSDP' 
    header += b'\x00' * 4
    return header

class _ProSafeOption:
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

class _ProSafeOptionString(_ProSafeOption):
    def __init__(self, option_id, option_name, option_desc):
        _ProSafeOption.__init__(self, option_id, option_name, option_desc)
    def build_set_packet_data(self, s):
        data = struct.pack(">H", self.option_id)
        data += struct.pack(">H", len(s))
        data += s.encode()
        return data

class _ProSafeOptionMAC(_ProSafeOption):
    def __init__(self, option_id, option_name, option_desc):
        _ProSafeOption.__init__(self, option_id, option_name, option_desc)
    def build_set_packet_data(self, mac):
        data = struct.pack(">H", self.option_id)
        data += struct.pack(">H", 6)
        data += hw_pton(mac)
        return data

class _ProSafeOptionIPv4(_ProSafeOption):
    def __init__(self, option_id, option_name, option_desc):
        _ProSafeOption.__init__(self, option_id, option_name, option_desc)
    def build_set_packet_data(self, addr):
        data = struct.pack(">H", self.option_id)
        data += struct.pack(">H", 4)
        data += socket.inet_pton(socket.AF_INET, addr)
        return data

class _ProSafeOptionBoolean(_ProSafeOption):
    def __init__(self, option_id, option_name, option_desc):
        _ProSafeOption.__init__(self, option_id, option_name, option_desc)
    def build_set_packet_data(self, boolean):
        data = struct.pack(">H", 1)
        if boolean:
            data += struct.pack(">b", 1)
        else:
            data += struct.pack(">b", 0)
        return data

class _ProSafeOptions:
    def __init__(self):
        self.options_by_id = { }
        self.options_by_name = { }
    def __getitem__(self, index):
        if index in self.options_by_id:
            return self.options_by_id[index]
        else:
            return self.options_by_name[index]
    def define(self, option_id, option_type, option_name, option_desc):
        if option_type == "string":
            option_class = _ProSafeOptionString
        elif option_type == "mac":
            option_class = _ProSafeOptionMAC
        elif option_type == "ipv4":
            option_class = _ProSafeOptionIPv4
        elif option_type == "bool":
            option_class = _ProSafeOptionBoolean
        option = option_class(option_id, option_name, option_desc)
        self.options_by_id[option_id] = option
        self.options_by_name[option_name] = option
        return option

_options_data = [
    [ 0x0001, "string", "model",        "Model" ],
    [ 0x0003, "string", "name",         "Name"  ],
    [ 0x0006, "ipv4",   "ipv4addr",     "IPv4 address" ],
    [ 0x0007, "ipv4",   "ipv4netmask",  "IPv4 netmask" ],
    [ 0x0008, "ipv4",   "ipv4gateway",  "IPv4 gateway" ],
    [ 0x000B, "bool",   "use_dhcp",     "Use DHCP?" ],
    [ 0x000D, "string", "firmware_ver", "Firmware version" ],
    [ 0xFFFF, "string", "end",          "End of options marker" ],
]
nsdp_options = _ProSafeOptions()
for option in _options_data:
    nsdp_options.define(option[0], option[1], option[2], option[3])

def _parse_packet(packet):
    if len(packet) < 24:
        raise ProSafePacketTooShort()
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
    parsed["protocol"] = packet[24:28].decode()
    # packet[28:32] unknown
    pos = 32
    while pos < len(packet):
        if len(packet) - pos < 4:
            raise ProSafeBadPacket("Truncated packet")
        option_id = struct.unpack(">H", packet[pos:pos+2])[0]
        option_len = struct.unpack(">H", packet[pos+2:pos+4])[0]
        pos = pos + 4
        if len(packet) - pos < option_len:
            raise ProSafeBadPacket("Truncated packet")
        option_data = packet[pos:pos+option_len]
#        option = 
        pos = pos + option_len
    return parsed

class ProSafeDiscover:
    def _setup(self, iface_info):
        """
        """
        # make sure that we have both a MAC (hardware) address and 
        # an IPv4 address for this interface
        # note: if we have multiple hardware or IPv4 addresses we will
        #       just use the first one 
        if not 'hw' in iface_info:
            raise ProSafeInterfaceNoMACAddress()
        if not 'ipv4' in iface_info:
            raise ProSafeInterfaceNoIPv4Address()
        self.mac = iface_info['hw'][0]['addr']
        self.ip = iface_info['ipv4'][0]['addr']

        self.src_mac_bin = hw_pton(self.mac)
        self.dst_mac_bin = hw_pton('00:00:00:00:00:00')

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('255.255.255.255', PROSAFE_RECV_PORT))

        self.seq_num = None

    def __init__(self, interface_name): 
        """
        """
        ifaddrs = getifaddrs.getifaddrs()
        if not interface_name in ifaddrs:
            raise ProSafeInterfaceNotFound()
        self._setup(ifaddrs[interface_name])

    def send(self):
        self.seq_num = struct.unpack("h", rand_bytes(2))[0]
        packet = _build_header(PROSAFE_MSG_QUERY_REQUEST, 
                               self.src_mac_bin, self.dst_mac_bin, self.seq_num)
        options = [ "model", "name", "mac", "ipv4addr", "firmware_ver" ]
        for option in options:
            packet += nsdp_options["model"].build_query_packet_data()
        packet += nsdp_options["end"].build_query_packet_data()
        self.sock.sendto(packet, ('255.255.255.255', PROSAFE_SEND_PORT))

    def recv(self):
        # loop here chucking out packets that are not for us...
        # bad seq_num, msg_type, ...?
        (rlist, wlist, xlist) = select.select([self.sock], [], [], 1)
        if self.sock in rlist:
            (data, srcaddr) = self.sock.recvfrom(8192)
            return _parse_packet(data)

class ProSafe:
    pass

psd = ProSafeDiscover('eth0')
psd.send()
print(psd.recv())

# TODO tests!
#hw_pton('sdf') -> fail
#hw_pton('20:cf:30:70:f2:db') -> work
#hw_pton('20cf3070f2db') -> work
#hw_pton('    20CF3070f2Db') -> work
#hw_pton('    20CF3  070f2Db') -> fail
#hw_pton('00') -> fail
#hw_pton('') -> fail

