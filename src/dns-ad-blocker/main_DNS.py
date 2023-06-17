import socket
from scapy.all import *
from scapy.layers.dns import DNS, UDP, IP

import DNS_record_interpreter
from DNS_record_display import display_DNS_query, display_DNS_response

# create a IPv4 socket, UDP
simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# bind the socket to port 53
simple_udp.bind(('0.0.0.0', 53))

try: 
    while True:
        request, adresa_sursa = simple_udp.recvfrom(65535)
        # convert the payload into scapy package
        packet = DNS(request)
        dns = packet.getlayer(DNS)
        
        # handle DNS queries only
        if dns is not None and dns.opcode == 0 and dns.qr == 0: 
            display_DNS_query(dns)

            # handle A records request
            if dns.qd.qtype == 1:
                dns_response = DNS_record_interpreter.single_record_lookup(dns)
                display_DNS_response(dns_response)

                simple_udp.sendto(bytes(dns_response), adresa_sursa)
            
            # handle NS records request
            elif dns.qd.qtype == 2:
                dns_response = DNS_record_interpreter.multiple_records_lookup(dns)
                display_DNS_response(dns_response)
                
                simple_udp.sendto(bytes(dns_response), adresa_sursa)

            # handle CNAME records request
            elif dns.qd.qtype == 5:
                dns_response = DNS_record_interpreter.single_record_lookup(dns)
                display_DNS_response(dns_response)

                simple_udp.sendto(bytes(dns_response), adresa_sursa)    
            
            # handle MX records request
            elif dns.qd.qtype == 15:
                dns_response = DNS_record_interpreter.multiple_records_lookup(dns)
                display_DNS_response(dns_response)
                
                simple_udp.sendto(bytes(dns_response), adresa_sursa)

            # handle AAAA records request
            elif dns.qd.qtype == 28:
                dns_response = DNS_record_interpreter.single_record_lookup(dns)
                display_DNS_response(dns_response)

                simple_udp.sendto(bytes(dns_response), adresa_sursa)    

            # otherwise, if the request requires other records,
            # let the DNS server from google handle it
            else:
                dns_response = sr1(IP(dst = '8.8.8.8') / UDP(dport = 53) / dns, verbose = 0)
                display_DNS_response(dns_response)

                simple_udp.sendto(bytes(dns_response), adresa_sursa)
finally: 
    simple_udp.close()