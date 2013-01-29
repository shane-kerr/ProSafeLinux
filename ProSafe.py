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

class ProSafeException(Exception): pass
class ProSafeInterfaceNotFound(ProSafeException): pass

class ProSafeDiscover:
    def __init__(self, interface_name): 
        """
        """
        ifaddrs = getifaddrs.getifaddrs()
        if not interface_name in ifaddrs:
            raise ProSafeInterfaceNotFound()
        iface_info = ifaddrs[interface_name]
        print(iface_info)
#        self.interface_info = {}
#        for interface in interfaces:
#            self.interface_info[interface] = {
#                "name": interface,
#            }
#        print(self.interface_info)

class ProSafe:
    pass

psd = ProSafeDiscover('eth0')
