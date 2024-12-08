## Files

- [bad_word_filter.py](https://github.com/matheus-delazeri/packet-filter/blob/main/bad_word_filter.py) - lib containing the function to filter bad words in the payload of packets. Can be runned independently in switches/routers but requires a routing script;
- [routing.py](https://github.com/matheus-delazeri/packet-filter/blob/main/routing.py) - handles routing using Vector-Distance algorithm. Should be runned in every switch/router of the topology. It includes the bad word filter lib automatically;
```
usage: routing.py [-h] --node NODE [--filter {bad_word}] [--bad_word_file BAD_WORD_FILE]

Router Configuration

options:
  -h, --help            show this help message and exit
  --node NODE           Name of the node to be used as router. e.g: r1
  --filter {bad_word}   Filter to be applied for packet's forwarding. e.g: 'bad_word' will replace all badwords found in a
                        payload.
  --bad_word_file BAD_WORD_FILE
                        File (txt) containing the bad words to filter.

```
- [topology.py](https://github.com/matheus-delazeri/packet-filter/blob/main/topology.py) - creates a topology in Mininet.
```
usage: topology.py [-h] [--topo {Basic,Mesh,ThreeRouters,TwoPaths}]

Run a Mininet topology

options:
  -h, --help            show this help message and exit
  --topo {Basic,Mesh,ThreeRouters,TwoPaths}
                        Choose the topology to run (default: Basic). Options: Basic, Mesh, ThreeRouters, TwoPaths.
```


### For testing
- [send_packet.py](https://github.com/matheus-delazeri/packet-filter/blob/main/send_packet.py) - send a packet with a specified payload to a given IP.
```
usage: send_packet.py [-h] [-p PAYLOAD] [--port PORT] [--protocol {tcp,udp}] destination

Send custom network packet

positional arguments:
  destination           Destination IP address

options:
  -h, --help            show this help message and exit
  -p PAYLOAD, --payload PAYLOAD
                        Payload to send (default: "This is a badword test")
  --port PORT           Destination port (default: 5000)
  --protocol {tcp,udp}  Network protocol (default: tcp)
```

- [sniff.py](https://github.com/matheus-delazeri/packet-filter/blob/main/sniff.py) - sniff a given interface of the current host and show all packets received. Note: by default, it assumes it will be runned at the BasicTopo at 'h2' host. The interface must be manually changed in this file when using a different topology.


## Example

1. Open a terminal and start the basic a topology by running:
```
python3 topology.py
```
2. Run, in the Mininet terminal, the following line to open a xterm terminal for each node of the topology (h1, h2 and r):
```
xterm h1 h2 r &
```
3. Start the routing script in the router node terminal ('r') by running:
```
python3 routing.py --node r --filter bad_word
```
4. Now, in the h2 terminal, start the sniff script, to display all incoming packets:
```
python3 sniff.py
```
5. Finally, in the h1 terminal, run the send_packet.py script, to send a packet to h2.
```
python3 send_packet.py 10.2.2.1 --payload A badword test!
```

If the setup was correct, you will be able to see the packet received in h2 with the word "badword" replaced by "****"!
