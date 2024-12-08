#!/usr/bin/env python

from scapy.all import *

def example(pkt):
    if pkt.haslayer(TCP):
        pkt[TCP].show()

sniff(iface='h2-eth0', prn=example)
