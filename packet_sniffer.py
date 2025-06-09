import socket
import struct
from datetime import datetime
from scapy.all import wrpcap, Ether
import threading
import sys
import termios
import tty
import select

captured_packets = []
stop_sniffing = False

def key_listener():
    global stop_sniffing
    print("Press 's' to stop and save PCAP.")
    while not stop_sniffing:
        if kbhit():
            ch = get_char()
            if ch.lower() == 's':
                stop_sniffing = True

def kbhit():
    dr, _, _ = select.select([sys.stdin], [], [], 0)
    return bool(dr)

def get_char():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

# Main function
def main():
    global stop_sniffing
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  # Use AF_PACKET on Linux
    listener_thread = threading.Thread(target=key_listener, daemon=True)
    listener_thread.start()

    while not stop_sniffing:
        raw_data, addr = conn.recvfrom(65536)
        eth = Ether(raw_data)
        captured_packets.append(eth)
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

            elif proto == 1:
                icmp_type, code, checksum = icmp_packet(data)
                print("\n>>> ICMP Packet")
                print(f"Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
            else:
                print('\nOther IPv4 Data:')
                print(format_multi_line('    ', data))
                
        elif eth_proto == 1544:
            arp_info = arp_packet(data)
            print(f"\n--- ARP Packet ---")
            for key, val in arp_info.items():
                print(f"{key}: {val}")
        else:
            print(f"\n[Other Ethernet Data]")
            print(format_multi_line('    ', data))
    
    # Save captured packets as .pcap only once after stopping
    if captured_packets:
        filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}_final.pcap"
        wrpcap(filename, captured_packets)
        print(f"\n[Capture stopped and saved to {filename}]")

# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac),socket.ntohs(proto), data[14:]

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

# Unpack ICMP Packets
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum

# Unpack ARP Packets
def arp_packet(data):
    if len(data) < 28:
        return {'Error': 'Incomplete ARP packet'}
    arp_hdr = struct.unpack('!HHBBH6s4s6s4s', data[:28])
    return {
        'Hardware Type': arp_hdr[0],
        'Protocol Type': arp_hdr[1],
        'Hardware Size': arp_hdr[2],
        'Protocol Size': arp_hdr[3],
        'Opcode': arp_hdr[4],
        'Sender MAC': get_mac_addr(arp_hdr[5]),
        'Sender IP': ipv4(arp_hdr[6]),
        'Target MAC': get_mac_addr(arp_hdr[7]),
        'Target IP': ipv4(arp_hdr[8])
    }

# Format multi-line payload data as ASCII
def format_multi_line(prefix, data, width=16):
    if isinstance(data, bytes):
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            hex_bytes = ' '.join(f'{b:02x}' for b in chunk)
            ascii_bytes = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f"{prefix}{i:04x}   {hex_bytes:<{width*3}}   {ascii_bytes}")
        return '\n'.join(lines)
    return str(data)

if __name__ == "__main__":
    main()

