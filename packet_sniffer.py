import socket
import struct

# Main function
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  # Use AF_PACKET on Linux

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("\n=== Ethernet Frame ===")
        print(f'Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}')

        # IPv4
        if eth_proto == 8: 
            version, header_length, ttl, proto, src_ip, dest_ip, data = ipv4_packet(data)
            print(f'\n--- IPv4 Packet ---')
            print(f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'Protocol: {proto}, Source IP: {src_ip}, Destination IP: {dest_ip}')

            # TCP
            if proto == 6:
                src_port, dest_port, seq, ack, flags, payload = tcp_segment(data)
                print(f'\n>>> TCP Segment')
                print(f'Src Port: {src_port}, Dest Port: {dest_port}')
                print(f'Sequence: {seq}, Acknowledgment: {ack}')
                print(f'Flags: {flags}')
                print('Payload (Hex & ASCII):')
                print(format_multi_line('    ', payload))

                # Optional HTTP sniff
                if src_port == 80 or dest_port == 80:
                    try:
                        http_data = payload.decode('utf-8')
                        print("\n[HTTP DATA]")
                        print(http_data)
                    except:
                        pass

            # UDP
            elif proto == 17:
                src_port, dest_port, size, payload = udp_segment(data)
                print(f'\n>>> UDP Segment')
                print(f'Src Port: {src_port}, Dest Port: {dest_port}, Length: {size}')
                print('Payload (Hex & ASCII):')
                print(format_multi_line('    ', payload))

                # Optional DNS sniff
                if src_port == 53 or dest_port == 53:
                    print("\n[DNS Packet Detected]")

            else:
                print('\nOther IPv4 Data:')
                print(format_multi_line('    ', data))

# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac),socket.htons(proto), data[14:]

# Return formatted MAC
def get_mac_addr(bytes_addr):
    bytes_str=map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Convert raw IP to dotted string
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpack TCP segment
def tcp_segment(data):
    (src_port, dest_port, seq, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        'URG': (offset_reserved_flags & 32) >> 5,
        'ACK': (offset_reserved_flags & 16) >> 4,
        'PSH': (offset_reserved_flags & 8) >> 3,
        'RST': (offset_reserved_flags & 4) >> 2,
        'SYN': (offset_reserved_flags & 2) >> 1,
        'FIN': offset_reserved_flags & 1
    }
    return src_port, dest_port, seq, ack, flags, data[offset:]

# Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H H 2x', data[:8])
    return src_port, dest_port, size, data[8:]

# Format multi-line payload data as hex + ASCII
def format_multi_line(prefix, string, size=80):
    if isinstance(string, bytes):
        hex_str = ''.join(r'\x{:02x}'.format(b) for b in string)
        ascii_str = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in string)
        wrapped = textwrap.wrap(hex_str, size)
        lines = []
        for i, line in enumerate(wrapped):
            ascii_line = ascii_str[i * (size // 4):(i + 1) * (size // 4)]
            lines.append(f"{prefix}{line}    {ascii_line}")
        return '\n'.join(lines)
    return string

if __name__ == "__main__":
    main()

