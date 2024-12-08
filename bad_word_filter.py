from scapy.all import *
import re
import logging

class PacketFilter:
    def __init__(self, bad_words_file=None):
        """
        Initialize dynamic packet filter
        
        :param bad_words_file: Optional path to file with bad words 
        """
        logging.basicConfig(
            level=logging.INFO, 
            format='%(asctime)s - PACKET FILTER - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

        if bad_words_file:
            try:
                with open(bad_words_file, 'r') as f:
                    self.bad_words = [word.strip().lower() for word in f.readlines() if word.strip()]
            except FileNotFoundError:
                self.logger.warning(f"Bad words file {bad_words_file} not found. Using default list.")
                self.bad_words = self._default_bad_words()
        else:
            self.bad_words = self._default_bad_words()
        
        self.bad_word_patterns = [
            re.compile(r'\b{}\b'.format(re.escape(word)), re.IGNORECASE) 
            for word in self.bad_words
        ]

    def _default_bad_words(self):
        """
        Provide a default list of bad words
        
        :return: List of default bad words
        """
        return [
            'badword', 'offensive', 'inappropriate', 
            'vulgar', 'profane', 'racist', 
            'sexist', 'hate', 'discriminate'
        ]

    def filter_packet(self, packet):
        """
        Filter packet content and modify if bad words detected
        
        :param packet: Scapy packet to filter
        :return: Modified or original packet
        """
        try:
            payload_layers = [TCP, UDP, SCTP, Raw]
            
            modified = False
            
            for layer_type in payload_layers:
                if packet.haslayer(layer_type):
                    try:
                        payload = bytes(packet[layer_type].payload).decode('utf-8', errors='ignore')
                        
                        def censor_word(match):
                            nonlocal modified
                            modified = True
                            return '*' * len(match.group(0))
                        
                        for pattern in self.bad_word_patterns:
                            payload = pattern.sub(censor_word, payload)
                        
                        if modified:
                            packet[layer_type].load = payload.encode('utf-8')
                            
                            # Recalculate checksums
                            if packet.haslayer(IP):
                                del packet[IP].len
                                del packet[IP].chksum
                            if packet.haslayer(TCP):
                                del packet[TCP].chksum
                            
                            self.logger.info(f"Packet modified: Bad words detected and filtered")
                            return packet
                    
                    except Exception as e:
                        self.logger.error(f"Payload decoding error: {e}")
            
            return packet
        
        except Exception as e:
            self.logger.error(f"Packet filtering error: {e}")
            return packet

def packet_handler(filter_instance):
    """
    Create a packet handler function for sniffing
    
    :param filter_instance: PacketFilter instance
    :return: Function to handle packets
    """
    def handler(packet):
        # Filter and forward packet
        modified_packet = filter_instance.filter_packet(packet)
        
        # Resend the packet
        if modified_packet:
            try:
                # Send packet back to the network
                sendp(modified_packet,verbose=False)
            except Exception as e:
                filter_instance.logger.error(f"Packet forwarding error: {e}")
    
    return handler

def start_packet_filtering(bad_words_file=None):
    """
    Start packet filtering on specified interface
    
    :param bad_words_file: Optional file with bad words
    """
    packet_filter = PacketFilter(bad_words_file)
    
    interfaces = list(conf.ifaces.keys())
    interfaces.remove('lo')

    packet_filter.logger.info(f"Starting packet filtering on interfaces: {interfaces}")
    
    try:
        sniff(
            iface=interfaces,
            prn=packet_handler(packet_filter), 
            store=0
        )
    except Exception as e:
        packet_filter.logger.error(f"Packet sniffing error: {e}")

if __name__ == '__main__':
    start_packet_filtering()
