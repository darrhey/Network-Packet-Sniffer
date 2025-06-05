import socket
import struct


# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac),socket.htons(proto), data[14:]

# Return formatted MAC
def get_mac_addr(bytes_addr):
    bytes_str=map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Trying to edit
