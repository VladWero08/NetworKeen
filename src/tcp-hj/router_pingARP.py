from scapy.all import * 

# ping(ARP request pe broadcast) necesar ca server-ul sa aibe router-ul in tabela lui ARP 
send(ARP(op=1, pdst="198.7.0.2", hwdst="ff:ff:ff:ff:ff:ff"))