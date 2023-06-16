# BIBLIOGRAFIE https://www.google.com/search?q=icmp+echo+reply+type+code&oq=ICMP+Echo+Reply&aqs=chrome.2.69i57j0i512l4j0i22i30l5.1788j0j4&sourceid=chrome&ie=UTF-8

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


# aici tinem informatiile geografice despre ip-uri
IP_address_informations = {}

# port unreachable ca sa primim ""ICMP Destination/PORT Unreachable" de la server-ul tinta

#port default, numarul de hopuri si timeout-ul(timp de asteptare al reply-ului)
def traceroute(ip, port = 33434, TTL = 64, timeout = 3):
    
    # UDP socket
    udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)

    # RAW socket pentru citirea reply-urilor ICMP
    icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    
    #setam time-out-ul pentru socket
    icmp_recv_socket.settimeout(timeout)

    for ttl in range(1, TTL + 1):
        # setam ttl-ul in header-ul IP
        udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        # trimitem mesaj UDP catre (IP, port)
        start_time = time.time()
        udp_send_sock.sendto(b'salut', (ip, port))

        try:
            
            ICMP_data, addr = icmp_recv_socket.recvfrom(63535)
            end_time = time.time()
            
            # primii 20 bytes sunt header-ul de IP
            router_ip = addr[0]
            icmp_type = ICMP_data[20]
            icmp_code = ICMP_data[21]

            # raspunsul este ICMP Time Exceeded message
            if icmp_type == 11 and icmp_code == 0:
                get_ip_info.inspect_IP_addresses(router_ip, IP_address_informations) # IP_address_informations preiau informatiile geografice folosind ipinfo
                print(f'{ttl}: {router_ip} {end_time - start_time}s')

            # raspunsul este ICMP Echo Reply message, inseamna ca am ajuns la destinatie 
            elif icmp_type == 0 and icmp_code == 0:
                print('we have reached the destination', end=' ')
                get_ip_info.inspect_IP_addresses(router_ip, IP_address_informations)
                print(f'{ttl}: {router_ip} {end_time - start_time}s')
                break

        except KeyboardInterrupt:
            # inchidem socket-urile
            udp_send_sock.close()
            icmp_recv_socket.close()

        except Exception as e:
            print('*')
            #print("Socket timeout ", str(e))
            #print(traceback.format_exc())
            #print (addr)
            continue

    # inchidem socket-urile
    udp_send_sock.close()
    icmp_recv_socket.close()

# pentru statistica, de pe ce ip facem request-ul
def get_my_ip():
    response = requests.get('https://api.ipify.org?format=json')
    data = response.json()
    return data['ip']

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
          

ip = input('adresa IP sau nume domeniu : ')
functional_traceroute(ip)


print('locations of the encountered IPs')
get_ip_info.display_route(IP_address_informations)

print('plotting:')
process_route.plot_route_in_world_map(IP_address_informations)

# fake_HTTP_header = {
#                     'referer': 'https://ipinfo.io/',
#                     'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36'
#                    }
# raspuns = requests.get('https://ipinfo.io/widget/193.226.51.6', headers=fake_HTTP_header)
# print (raspuns.json())