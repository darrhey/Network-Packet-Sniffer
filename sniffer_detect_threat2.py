import socket
import struct
import textwrap
from datetime import datetime
from scapy.all import wrpcap, Ether
import threading
import sys
import termios
import tty
import select

captured_packets = []
alert_packets = []
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

def main():
    global stop_sniffing
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    listener_thread = threading.Thread(target=key_listener, daemon=True)
    listener_thread.start()

    print("Sniffing started. Waiting for traffic...\n")

    while not stop_sniffing:
        raw_data, _ = conn.recvfrom(65536)
        eth = Ether(raw_data)
        captured_packets.append(eth)

        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print(f"\n=== Ethernet Frame ===")
        print(f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")

        if eth_proto == 8:  # IPv4
            version, header_length, ttl, proto, src_ip, dest_ip, data = ipv4_packet(data)
            print(f"--- IPv4 Packet ---")
            print(f"Version: {version}, TTL: {ttl}, Protocol: {proto}")
            print(f"Source IP: {src_ip}, Destination IP: {dest_ip}")

            if proto == 6:  # TCP
                src_port, dest_port, seq, ack, flags, payload = tcp_segment(data)
                print(f">>> TCP Segment: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")
                print(f"Flags: {flags}")
                print(format_multi_line("    ", payload))

                if detect_tcp_threat(src_port, dest_port, flags):
                    print(f"[!] Possible TCP Threat Detected from {src_ip}:{src_port}")
                    alert_packets.append(eth)

            elif proto == 17:  # UDP
                src_port, dest_port, length, payload = udp_segment(data)
                print(f">>> UDP Segment: {src_ip}:{src_port} -> {dest_ip}:{dest_port}, Length: {length}")
                print(format_multi_line("    ", payload))

                if detect_dns_tunnel(src_port, dest_port, payload):
                    print(f"[!] Suspicious DNS Activity from {src_ip}:{src_port}")
                    alert_packets.append(eth)

            elif proto == 1:  # ICMP
                icmp_type, code, checksum = icmp_packet(data)
                print(f">>> ICMP Packet Type {icmp_type} Code {code}")
                if icmp_type == 8:
                    print(f"[!] ICMP Echo Request (Ping) from {src_ip}")
                    alert_packets.append(eth)

        elif eth_proto == 1544:  # ARP
            arp_info = arp_packet(data)
            print(f"--- ARP Packet ---")
            for key, val in arp_info.items():
                print(f"{key}: {val}")
            if arp_info.get('Opcode') == 2 and arp_info.get('Sender MAC') == '00:00:00:00:00:00':
                print(f"[!] Suspicious ARP Reply from {arp_info.get('Sender IP')}")
                alert_packets.append(eth)

        else:
            print(f"[Other Ethernet Protocol Data]")
            print(format_multi_line("    ", data))

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if captured_packets:
        wrpcap(f"capture_{timestamp}_final.pcap", captured_packets)
        print(f"\n[+] All packets saved to capture_{timestamp}_final.pcap")
    if alert_packets:
        wrpcap(f"alert_{timestamp}.pcap", alert_packets)
        print(f"[!] Suspicious packets saved to alert_{timestamp}.pcap")

def detect_tcp_threat(src_port, dest_port, flags):
    # SYN flood detection: only SYN, no ACK, typically on port 80/443
    if flags['SYN'] == 1 and flags['ACK'] == 0 and (dest_port == 80 or dest_port == 443):
        return True
    # Null scan (no flags)
    if sum(flags.values()) == 0:
        return True
    # Xmas scan
    if flags['FIN'] and flags['URG'] and flags['PSH']:
        return True
    return False

def detect_dns_tunnel(src_port, dest_port, payload):
    # Avoid false positives for normal DNS (use higher length)
    return (src_port == 53 or dest_port == 53) and len(payload) > 150

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.ntohs(proto), data[14:]

def get_mac_addr(bytes_addr):
    return ':'.join(f'{b:02x}' for b in bytes_addr).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    src_port, dest_port, seq, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
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

def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H H 2x', data[:8])
    return src_port, dest_port, length, data[8:]

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum

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
