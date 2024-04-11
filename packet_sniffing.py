import argparse
from scapy.all import sniff

def packet_handler(packet):
    # print summary
    print(packet.summary())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-i", "--interface", default=None, help="interface to sniff on (default: all)")
    parser.add_argument("-c", "--count", type=int, default=10, help="amount of packets to sniff (default: 10)")
    args = parser.parse_args()

    interface = args.interface
    count = args.count

    print(f"Sniffing:{count} packets on interface:{interface}")

    # start (uses builtin loop from library for the amount of packets)
    sniff(iface=interface, prn=packet_handler, count=count)
