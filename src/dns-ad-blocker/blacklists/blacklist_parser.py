from scapy.all import *
from scapy.layers.dns import DNS, DNSRR

def get_adservers_list(blacklist_path):
    adserver = open(blacklist_path)
    domains = adserver.readlines()
    domains_list = []

    # pentru fiecare domeniu din lista, stergem IP-ul 0.0.0.0 de la
    # inceput si endline-ul de la sfarsit
    for cnt in range(10, len(domains)):
        domains_list.append(domains[cnt].split()[1])

    return domains_list

# functie care va genera un raspuns care redirectioneaza
# request-ul spre 0.0.0.0 / :: 
def get_ad_blocker_response(DNS_packet):
    with open("./src/dns-ad-blocker/blacklists/blocked_domains.txt", "a") as blocked:
        blocked.write("Blocked: " + DNS_packet.qd.qname.decode("utf-8") + "\n")
    
    # daca request-ul este de tip AAAA asteapta o adresa IPv6
    rdata_addresss = "0.0.0.0" if DNS_packet.qd.qtype != 28 else "::"

    DNS_answer = DNSRR(
        rrname = DNS_packet[DNS].qd.qname,
        ttl = 500,
        type = DNS_packet[DNS].qd.qtype,
        rclass = "IN",
        rdata = rdata_addresss
    )
    
    DNS_response = DNS(
        id = DNS_packet[DNS].id,
        qr = 1,
        aa = 0,
        rcode = 0,
        qd = DNS_packet.qd,
        an = DNS_answer
    )

    return DNS_response