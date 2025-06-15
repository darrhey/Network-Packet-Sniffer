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

    print("Sniffing started. Waiting for traffic...")

    while not stop_sniffing:
        raw_data, _ = conn.recvfrom(65536)
        eth = Ether(raw_data)
        captured_packets.append(eth)

        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        if eth_proto == 8:
            version, header_length, ttl, proto, src_ip, dest_ip, data = ipv4_packet(data)
            if proto == 6:
                src_port, dest_port, seq, ack, flags, payload = tcp_segment(data)
                if detect_tcp_threat(src_port, dest_port, flags):
                    print(f"[!] Possible TCP Threat Detected from {src_ip}:{src_port}")
                    alert_packets.append(eth)
            elif proto == 17:
                src_port, dest_port, length, payload = udp_segment(data)
                if detect_dns_tunnel(src_port, dest_port, payload):
                    print(f"[!] Suspicious DNS Activity from {src_ip}:{src_port}")
                    alert_packets.append(eth)
            elif proto == 1:
                icmp_type, code, checksum = icmp_packet(data)
                if icmp_type == 8:
                    print(f"[!] ICMP Echo Request Detected (Ping) from {src_ip}")
                    alert_packets.append(eth)
        elif eth_proto == 1544:
            arp_info = arp_packet(data)
            if arp_info.get('Opcode') == 2 and arp_info.get('Sender MAC') == '00:00:00:00:00:00':
                print(f"[!] Suspicious ARP Reply with empty MAC from {arp_info.get('Sender IP')}")
                alert_packets.append(eth)

    # Save captured and alert packets on stop
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if captured_packets:
        wrpcap(f"capture_{timestamp}_final.pcap", captured_packets)
        print(f"\n[+] Capture saved to capture_{timestamp}_final.pcap")
    if alert_packets:
        wrpcap(f"alert_{timestamp}.pcap", alert_packets)
        print(f"[!] Alert packets saved to alert_{timestamp}.pcap")

def detect_tcp_threat(src_port, dest_port, flags):
    # Basic checks: multiple SYNs, null scan, Xmas scan
    if flags['SYN'] == 1 and flags['ACK'] == 0:
        return True  # SYN flood attempt
    if sum(flags.values()) == 0:
        return True  # Null scan
    if flags['FIN'] and flags['URG'] and flags['PSH']:
        return True  # Xmas scan
    return False

def detect_dns_tunnel(src_port, dest_port, payload):
    if (src_port == 53 or dest_port == 53) and len(payload) > 100:
        return True
    return False

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

if __name__ == "__main__":
    main()
