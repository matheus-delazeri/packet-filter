#!/usr/bin/env python3

import argparse
from scapy.all import *

def send_custom_packet(destination_ip, payload, port=5000, protocol='tcp'):
    """
    Send a custom packet to a specified destination
    
    :param destination_ip: IP address of the destination host
    :param payload: Message payload to send
    :param port: Destination port (default 5000)
    :param protocol: Protocol to use (tcp or udp)
    """
    try:
        # Create IP packet
        ip_packet = IP(dst=destination_ip)
        
        # Select protocol
        if protocol.lower() == 'tcp':
            packet = ip_packet/TCP(dport=port)/payload
        elif protocol.lower() == 'udp':
            packet = ip_packet/UDP(dport=port)/payload
        else:
            print(f"Unsupported protocol: {protocol}")
            return
        
        # Send packet
        print(f"Sending packet:")
        print(f"- Destination: {destination_ip}")
        print(f"- Port: {port}")
        print(f"- Protocol: {protocol}")
        print(f"- Payload: {payload}")
        
        send(packet, verbose=True)
        print("Packet sent successfully!")
    
    except Exception as e:
        print(f"Error sending packet: {e}")

def main():
    # Setup argument parser
    parser = argparse.ArgumentParser(description='Send custom network packet')
    
    # Add arguments
    parser.add_argument('destination', 
                        help='Destination IP address')
    parser.add_argument('-p', '--payload', 
                        default='This is a badword test', 
                        help='Payload to send (default: "This is a badword test")')
    parser.add_argument('--port', 
                        type=int, 
                        default=5000, 
                        help='Destination port (default: 5000)')
    parser.add_argument('--protocol', 
                        choices=['tcp', 'udp'], 
                        default='tcp', 
                        help='Network protocol (default: tcp)')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Send packet
    send_custom_packet(
        destination_ip=args.destination, 
        payload=args.payload, 
        port=args.port, 
        protocol=args.protocol
    )

if __name__ == '__main__':
    main()
