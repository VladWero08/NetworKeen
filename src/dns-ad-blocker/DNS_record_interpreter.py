import random
from random import randrange
from scapy.all import *
from scapy.layers.dns import IP, UDP, DNS, DNSQR, DNSRR
from blacklists.blacklist_parser import get_adservers_list, get_ad_blocker_response

adservers = get_adservers_list("src/dns-ad-blocker/blacklists/adservers.txt") 
facebook = get_adservers_list("src/dns-ad-blocker/blacklists/facebook.txt")
root_servers_IP = ["192.36.148.17", "192.58.128.30", "192.5.5.241"] 

# raspunsul care va fi trimis in momentul
# in care va apararea o eroare 
def send_response_server_error(DNS_packet):
    DNS_error_response = DNS(
            id = DNS_packet[DNS].id,
            qr = 1,
            aa = 0,
            rcode = 2,                         # 2 = server-ul nu a reusit sa indeplineasca request-ul
            qd = DNS_packet.qd
        )
    
    return DNS_error_response

def send_request_root_server(DNS_packet):
    # alege random unul dintre serverele root
    root_ip = IP(dst = random.choice(root_servers_IP))
    transport = UDP(dport = 53)

    # print("Inside root with IP = " + root_ip.dst)

    # deoarece serverele root nu ofera cautarea recursiva, setam
    DNS_packet.rd = 0
    
    root_response = sr1(root_ip / transport / DNS_packet, verbose = 0, timeout = 2)

    if root_response is not None:
        # verificam daca raspunsul contine vreo eroare
        if root_response[DNS].rcode != 0:
            return root_response

        # trebuie sa fie cel putin 2 raspunsuri aditionale, pentru ca exista
        # cazul in care poate exista unul singur si acela sa fie de tipul OPT,
        # care contine cateva informatii aditionale
        if root_response.arcount > 1:
            ar_cnt = randrange(root_response.arcount)

            while root_response.ar[ar_cnt].type != 1:
                ar_cnt = randrange(root_response.arcount)

            resp = root_response.ar[ar_cnt]

        else:
            # daca nu exista raspunsuri aditionale, trebuie
            # sa cautam un numele unui NS care stie sa se ocupe de acest request
            ns_cnt = randrange(root_response.nscount)
            resp = root_response.ns[ns_cnt]

            # un request catre server-ul de la Google 
            # care va intoarce NS-ul dorit
            DNSRR_auth_query = DNSQR(qname = resp.rdata, qtype = 1, qclass = 1)
            DNSRR_auth_IP = sr1(IP(dst = '8.8.8.8') / UDP(dport = 53) / DNS(qd = DNSRR_auth_query, rd=1), verbose = 0, timeout = 2)
            resp = DNSRR_auth_IP[DNS].an

        return send_request_tld_server(DNS_packet, resp.rdata)
    else:
        # in cazul in care server-ul TLD nu returneaza un raspuns,
        # trimitem un raspuns in care anuntam ca request-ul nu a putut fi rezolvat de server
        return send_response_server_error(DNS_packet)

def send_request_tld_server(DNS_packet, TLD_ip):
    # print("Inside TLD with IP = " + TLD_ip)

    TLD_IP = IP(dst = TLD_ip)
    transport = UDP(dport = 53)

    TLD_response = sr1(TLD_IP / transport / DNS_packet, verbose = 0, timeout = 2)

    if TLD_response is not None:
        # verifica daca raspunsul contine erori
        if TLD_response[DNS].rcode != 0:
            return TLD_response

        # verifica daca este cazul in care TLD-ul 
        # intoarce record/recordurile dorite
        if TLD_response.ancount > 0:
            return TLD_response

        # trebuie sa fie cel putin 2 raspunsuri aditionale, pentru ca exista
        # cazul in care poate exista unul singur si acela sa fie de tipul OPT,
        # care contine cateva informatii aditionale
        elif TLD_response.arcount > 1:
            ar_cnt = randrange(TLD_response.arcount)

            while TLD_response.ar[ar_cnt].type != 1:
                ar_cnt = randrange(TLD_response.arcount)

            resp = TLD_response.ar[ar_cnt]
        else:
            # daca nu exista raspunsuri aditionale, trebuie
            # sa cautam un numele unui NS care stie sa se ocupe de acest request
            ns_cnt = randrange(TLD_response.nscount)
            DNSRR_auth = TLD_response.ns[ns_cnt]

            # daca primim un record de tip SOA, inseamna ca request-ul nu a fost indeplinit,
            # deci trebuie sa returnam acest raspuns
            if DNSRR_auth.type == 6:
                return TLD_response            

            # un request catre server-ul de la Google 
            # care va intoarce NS-ul dorit
            DNSRR_auth_query = DNSQR(qname = DNSRR_auth.rdata, qtype = 1, qclass = 1)
            DNSRR_auth_IP = sr1(IP(dst = '8.8.8.8') / UDP(dport = 53) / DNS(qd = DNSRR_auth_query, rd=1), verbose = 0, timeout = 2)

            if DNSRR_auth_IP is None:
                return DNSRR_auth_IP
            
            resp = DNSRR_auth_IP[DNS].an

        # trimitem mai departe request-ul pentru serverul authoritative
        return send_request_authoritative_server(DNS_packet, resp.rdata)
    else:
        # in cazul in care server-ul TLD nu returneaza un raspuns,
        # trimitem un raspuns in care anuntam ca request-ul nu a putut fi rezolvat de server
        return send_response_server_error(DNS_packet)


def send_request_authoritative_server(DNS_packet, authoritative_ip):
    # print("Inside authoritative with IP = " + authoritative_ip)

    auth_IP = IP(dst = authoritative_ip)
    transport = UDP(dport = 53)

    authoritative_resp = sr1(auth_IP / transport / DNS_packet, verbose = 0, timeout = 2)

    if authoritative_resp is not None:
        # daca request-ul nu este de tip NS, dar raspunsul este,
        # inseamna ca trebuie sa mai cautam in unul din NS-urile primite domeniul cautat
        if DNS_packet.qd.qtype != 2 and authoritative_resp.nscount > 0 and authoritative_resp.an is None:
            #cat timp authority returneaza NS si nu A, intrebam pe google adresa lui NS si dupa intrebam mai departe la adresa NS 
            while authoritative_resp is not None and authoritative_resp.nscount > 0 and authoritative_resp.ns.type == 2 and authoritative_resp.an is None:
                DNS_req = DNS(rd=1) # sa fie recursiv                  #A      # IN(clasa query) 
                DNS_req_qd = DNSQR(qname=authoritative_resp.ns.rdata, qtype=1, qclass=1) # numele serverului 
                DNS_req.qd = DNS_req_qd # cautam ip-ul pentru numele serverului

                # pentru a afla IP-ului NS-ului trimit un request catre google
                authoritative_resp = sr1(IP(dst = '8.8.8.8') / UDP(dport = 53) / DNS_req, verbose = 0, timeout = 2)
                # pentru a aflat IP-ului domeniunului trimit un request 
                # catre server-ul NS pe care l-am aflat la pasul anterior
                authoritative_resp = sr1(IP(dst = authoritative_resp.an.rdata) / UDP(dport = 53) / DNS_packet[DNS], verbose = 0, timeout = 2)
                
        # daca request-ul este de tip A / AAAA,
        # verifica daca nu cumva record-ul primit este CNAME, iar daca este
        # trimitem recursiv un request catre server-ul nostru pentru a intoarce adresa IP pentru acel CNAME
        if (DNS_packet.qd.qtype == 1 or DNS_packet.qd.qtype == 28) and authoritative_resp.an is not None and authoritative_resp.an.type == 5:
            DNS_req = DNS()
            DNS_req_qd = DNSQR(qname=authoritative_resp.an.rdata, qtype=DNS_packet.qd.qtype, qclass=1)
            DNS_req.qd = DNS_req_qd

            return send_request_root_server(DNS_req)
    
    return authoritative_resp     

def google_request(DNS_packet):
    return sr1(IP(dst = '8.8.8.8') / UDP(dport = 53) / DNS_packet, verbose = 0)

def single_record_lookup(DNS_packet):
    domain_requested = DNS_packet.qd.qname.decode()[:-1]

    # intai verifica daca cumva domeniul cerut este in 
    # lista cu domeniile care trebuie sa fie blocate
    if domain_requested in adservers or domain_requested in facebook:
        # daca este un domeniu care trebuie blocat, intoarcem un raspuns care
        # redirectioneaza spre adresa '0.0.0
        return get_ad_blocker_response(DNS_packet)

    response = send_request_root_server(DNS_packet)

    # daca un raspuns a fost gasit, trebuie filtrat
    if response is not None:
        DNS_response = response[DNS]
        DNS_response.id = DNS_packet[DNS].id    # raspunsul trebuie sa aiba ID-ului request-ului initial primit pe server-ul nostru
        DNS_response.aa = 0                     # nu putem spune ca suntem server-ul authoritative :)
        DNS_response.qd = DNS_packet.qd         # raspunsul trebuie sa aiba query-ul identic cu query-ul request-ului initial

        return DNS_response
    
    else:
        # daca un raspuns nu a putut fi gasit,
        # trimitem un raspuns in care anuntam ca request-ul nu a putut fi rezolvat de server
        return send_response_server_error(DNS_packet)
    
def multiple_records_lookup(DNS_packet):
    domain_requested = DNS_packet.qd.qname.decode()[:-1]

    # intai verifica daca cumva domeniul cerut este in 
    # lista cu domeniile care trebuie sa fie blocate
    if domain_requested in adservers or domain_requested in facebook:
        # daca este un domeniu care trebuie blocat, intoarcem un raspuns care
        # redirectioneaza spre adresa '0.0.0
        return get_ad_blocker_response(DNS_packet)
    
    response = send_request_root_server(DNS_packet)

    if response is not None:
        DNS_response = response[DNS]
        DNS_response.id = DNS_packet[DNS].id    # raspunsul trebuie sa aiba ID-ului request-ului initial primit pe server-ul nostru
        DNS_response.aa = 0                     # nu putem spune ca suntem server-ul authoritative :)
        DNS_response.qd = DNS_packet.qd 

        # daca nu a fost vreo eroare si exista raspunsuri
        if DNS_response.rcode == 0 and DNS_response.ancount > 0:
            # pentru fiecare raspuns in request-ul NS/MX, iteram prin lista de domenii
            # si verificam daca cumva se afla in lista de domenii care trebuie blocate
            for answer in range(DNS_response.ancount):
                NS_domain = DNS_response.an[answer].rdata.decode()[:-1] if DNS_packet.qd.qtype == 2 else DNS_response.an[answer].exchange.decode()[:-1]

                if NS_domain in adservers or NS_domain in facebook:
                    return get_ad_blocker_response(DNS_packet)

        return DNS_response
    
    else:
        # daca un raspuns nu a putut fi gasit,
        # trimitem un raspuns in care anuntam ca request-ul nu a putut fi rezolvat de server
        return send_response_server_error(DNS_packet)