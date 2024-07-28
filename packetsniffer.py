from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
import datetime
import json

def packet_callback(packet):
    """Process and display packet information with enhanced details."""
    packet_data = {
        'timestamp': str(datetime.datetime.now()),
        'src_ip': packet[IP].src if IP in packet else None,
        'dst_ip': packet[IP].dst if IP in packet else None,
        'protocol': packet[IP].proto if IP in packet else None,
        'payload': str(packet.payload),
    }

    if IP in packet:
        protocol = packet[IP].proto
        packet_data['protocol'] = protocol
        if protocol == 6:  # TCP
            if TCP in packet:
                packet_data['src_port'] = packet[TCP].sport
                packet_data['dst_port'] = packet[TCP].dport
        elif protocol == 17:  # UDP
            if UDP in packet:
                packet_data['src_port'] = packet[UDP].sport
                packet_data['dst_port'] = packet[UDP].dport
        elif protocol == 1:  # ICMP
            packet_data['icmp_type'] = packet[ICMP].type
            packet_data['icmp_code'] = packet[ICMP].code
        elif protocol == 17 and DNS in packet:  # DNS
            packet_data['dns_qd'] = packet[DNS].qd
            packet_data['dns_an'] = packet[DNS].an

    # Log packet data
    with open('packets_log.json', 'a') as log_file:
        json.dump(packet_data, log_file)
        log_file.write('\n')

    # Display packet information
    print(f"{datetime.datetime.now()} - Src: {packet_data['src_ip']} | Dst: {packet_data['dst_ip']} | Protocol: {packet_data['protocol']}")
    if 'src_port' in packet_data:
        print(f"Port: {packet_data['src_port']} | Dst Port: {packet_data['dst_port']}")
    if 'icmp_type' in packet_data:
        print(f"ICMP Type: {packet_data['icmp_type']} | Code: {packet_data['icmp_code']}")
    if 'dns_qd' in packet_data:
        print(f"DNS Query: {packet_data['dns_qd']}")
    if 'dns_an' in packet_data:
        print(f"DNS Answer: {packet_data['dns_an']}")

    print("-" * 50)

def main(interface):
    """Start packet sniffing with filters."""
    print(f"Starting packet sniffer on interface {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0, filter="ip")

if __name__ == "__main__":
    interface = "eth0"  # Replace with your network interface
    main(interface)
