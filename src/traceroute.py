# REFERENCES: 
# https://www.google.com/search?q=icmp+echo+reply+type+code&oq=ICMP+Echo+Reply&aqs=chrome.2.69i57j0i512l4j0i22i30l5.1788j0j4&sourceid=chrome&ie=UTF-8

import sys
sys.path.insert(1, 'src/traceroute-utilities')
import get_ip_info
import process_route
import socket
import requests
import time
import os
import subprocess
import re

file_path = 'src/traceroute-utilities/locations.txt'

# dictionary with geografical information about the IPs
IP_address_informations = {}

# 33434 ---> unreachable port, in order to get "ICMP Destination/PORT Unreachable"
def traceroute(ip, port = 33434, TTL = 64, timeout = 3):
    
    # UDP socket
    udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)

    # RAW socket for reading ICMP replies
    icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    
    # set timeout for the socket
    icmp_recv_socket.settimeout(timeout)

    for ttl in range(1, TTL + 1):
        # set the TTL in the header of IP
        udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        # send UDP message to (IP, 33434)
        start_time = time.time()
        udp_send_sock.sendto(b'salut', (ip, port))

        try:
            
            ICMP_data, addr = icmp_recv_socket.recvfrom(63535)
            end_time = time.time()
            
            # the frist 20 bytes will be the IP header
            router_ip = addr[0]
            icmp_type = ICMP_data[20]
            icmp_code = ICMP_data[21]

            # response is ICMP Time Exceeded message
            if icmp_type == 11 and icmp_code == 0:
                # get geographical information of the IP
                get_ip_info.inspect_IP_addresses(router_ip, IP_address_informations) 
                # print those informations
                print(f'{ttl}: {router_ip} {end_time - start_time}s')

            # response is ICMP Echo Reply message, 
            # means that the destination was reached
            elif icmp_type == 0 and icmp_code == 0:
                # get geographical information of the IP
                get_ip_info.inspect_IP_addresses(router_ip, IP_address_informations)

                print('We have reached the destination', end=' ')
                print(f'{ttl}: {router_ip} {end_time - start_time}s')
                break

        except KeyboardInterrupt:
            # close the sockets
            udp_send_sock.close()
            icmp_recv_socket.close()

        except Exception as e:
            print('*')
            continue

    # close the sockets
    udp_send_sock.close()
    icmp_recv_socket.close()

# for the statistics, the IP from which the
# request are made (our IP)
def get_my_ip():
    response = requests.get('https://api.ipify.org?format=json')
    data = response.json()
    return data['ip']

# alternative option for traceroute
def functional_traceroute(target):
    ip = socket.gethostbyname(target)
    command = ['traceroute', '-I', ip]
    result = subprocess.run(command, capture_output=True, text=True)
    output = result.stdout.strip()
    ip_addresses = set( re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', output) )

    for addr in ip_addresses:
        get_ip_info.inspect_IP_addresses(addr, IP_address_informations) 

    with open(file_path, 'a') as file:
        file.write('\n#######################################\n')
        my_ip = get_my_ip()
        file.write(f'destination {target} - {ip}, request made from ip {my_ip}\n')

        for IP_entry in IP_address_informations:
            file.write(f"ip: {IP_entry}, city: {IP_address_informations[IP_entry]['city']}, region: {IP_address_informations[IP_entry]['region']}, country: {IP_address_informations[IP_entry]['country']}\n")
          

ip = input('Adresa IP sau nume domeniu : ')
functional_traceroute(ip)

print('Locations of the encountered IPs:')
get_ip_info.display_route(IP_address_informations)

# plot the map
process_route.plot_route_in_world_map(IP_address_informations)
