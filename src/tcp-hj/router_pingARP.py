from scapy.all import * 

# send an ARP broadcast request to obtain the MAC address of the server
send(ARP(op=1, pdst="198.7.0.2", hwdst="ff:ff:ff:ff:ff:ff"))