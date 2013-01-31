import NSDP

nsdp = NSDP.DiscoverNSDP('eth0')
nsdp.send()
print(nsdp.recv())

# TODO tests!
#hw_pton('sdf') -> fail
#hw_pton('20:cf:30:70:f2:db') -> work
#hw_pton('20cf3070f2db') -> work
#hw_pton('    20CF3070f2Db') -> work
#hw_pton('    20CF3  070f2Db') -> fail
#hw_pton('00') -> fail
#hw_pton('') -> fail

