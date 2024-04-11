import argparse
from scapy.all import *

def network_scan(target, ports, timeout=1):
    open_ports = []

    # for each port
    for port in ports:
        syn_packet = IP(dst=target) / TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=timeout, verbose=False)

        # check for response
        if response is not None:
            # check for response to contains syn ack (0x12 = ack)
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                open_ports.append(port)
                # syn rst to close connection
                rst_packet = IP(dst=target) / TCP(dport=port, flags="R")
                send(rst_packet, verbose=False)
    return open_ports

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple network scanner")
    parser.add_argument("target_ip", help="IP address of the target host")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=[21, 22, 23, 143, 80, 443, 8080, 3389],
                        help="List of ports to scan (default: 21, 22, 23, 143, 80, 443, 8080, 3389)")
    args = parser.parse_args()

    target_ip = args.target_ip

    ports_scan = args.ports

    open_ports = network_scan(target_ip, ports_scan)

    if open_ports:
        print("Open ports on target:{}: {}".format(target_ip, open_ports))
    else:
        print("No ports found to be open {}".format(target_ip))
