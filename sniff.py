#!/usr/bin/env python

from scapy.all import *

def example(pkt):
    if pkt.haslayer(TCP):
        with open("test_result.json", 'r') as f:
            data = json.load(f)
            data["received"] += 0.5
            data["finished_at"] = time.time()

        with open("test_result.json", 'w') as f:
            json.dump(data, f)

        pkt[TCP].show()

sniff(iface='h2-eth0', prn=example)
