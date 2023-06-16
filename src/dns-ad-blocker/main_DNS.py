import socket
from scapy.all import *
from scapy.layers.dns import DNS, UDP, IP

import DNS_record_interpreter
from DNS_record_display import display_DNS_query, display_DNS_response

# creeam un socket IPv4, UDP
simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# ii oferim socket-ului portul 53
simple_udp.bind(('0.0.0.0', 53))

try: 
    while True:
        request, adresa_sursa = simple_udp.recvfrom(65535)
        # transformam payload-ul in packet scapy DNS
        packet = DNS(request)
        dns = packet.getlayer(DNS)
        
        # ne ocupam doar de DNS request-uri
        if dns is not None and dns.opcode == 0 and dns.qr == 0: 
            # formatam continutul request-ului si il afisam 
            display_DNS_query(dns)

            # request de tip A
            if dns.qd.qtype == 1:
                dns_response = DNS_record_interpreter.single_record_lookup(dns)
                display_DNS_response(dns_response)

                simple_udp.sendto(bytes(dns_response), adresa_sursa)
            
            # request de tip NS, name server
            elif dns.qd.qtype == 2:
                dns_response = DNS_record_interpreter.multiple_records_lookup(dns)
                display_DNS_response(dns_response)
                
                simple_udp.sendto(bytes(dns_response), adresa_sursa)

            # request de tip CNAME, canonical name
            elif dns.qd.qtype == 5:
                dns_response = DNS_record_interpreter.single_record_lookup(dns)
                display_DNS_response(dns_response)

                simple_udp.sendto(bytes(dns_response), adresa_sursa)    
            
            # hrequest de tip MX
            elif dns.qd.qtype == 15:
                dns_response = DNS_record_interpreter.multiple_records_lookup(dns)
                display_DNS_response(dns_response)
                
                simple_udp.sendto(bytes(dns_response), adresa_sursa)

            # request de tip AAAA
            elif dns.qd.qtype == 28:
                dns_response = DNS_record_interpreter.single_record_lookup(dns)
                display_DNS_response(dns_response)

                simple_udp.sendto(bytes(dns_response), adresa_sursa)    

            # il cazul in care este alt tip de request, trimitem request-ul
            # catre server-ul de la google
            else:
                dns_response = sr1(IP(dst = '8.8.8.8') / UDP(dport = 53) / dns, verbose = 0)
                display_DNS_response(dns_response)

                simple_udp.sendto(bytes(dns_response), adresa_sursa)
finally: 
    simple_udp.close()