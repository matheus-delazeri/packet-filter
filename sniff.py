#!/usr/bin/env python

from scapy.all import *

def example(pkt):
    pkt.show()

sniff(iface='h2-eth0', prn=example)
