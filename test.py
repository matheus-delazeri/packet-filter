from send_packet import send_custom_packet
import argparse
from scapy.all import *


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
    
    parser.add_argument('--count', 
                        type=int, 
                        default=1, 
                        help='Number of packets to be sent')
    
    # Parse arguments
    args = parser.parse_args()
    with open("test_result.json", 'w') as f:
        json.dump({"received": 0, "created_at": time.time()}, f)

    for i in range(0, args.count):
        send_custom_packet(
            destination_ip=args.destination, 
            payload=args.payload, 
            port=args.port, 
            protocol=args.protocol
        )
    time.sleep(args.count/100)
    with open("test_result.json", 'r') as f:
        data = json.load(f)
        received = data["received"]

    print("------------------------------------")
    print("Packets received: {}".format(received))
    print("Packet loss: {}%".format(((args.count - received) * 100) / args.count))
    print("(Total) Mean time per packet: {:.5f}s".format((data["finished_at"] - data["created_at"])/args.count))
    print("(Received) Mean time per packet: {:.5f}s".format((data["finished_at"] - data["created_at"])/received))



if __name__ == '__main__':
    main()

