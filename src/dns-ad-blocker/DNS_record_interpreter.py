import random
from random import randrange
from scapy.all import *
from scapy.layers.dns import IP, UDP, DNS, DNSQR, DNSRR
from blacklists.blacklist_parser import get_adservers_list, get_ad_blocker_response

adservers = get_adservers_list("src/dns-ad-blocker/blacklists/adservers.txt") 
facebook = get_adservers_list("src/dns-ad-blocker/blacklists/facebook.txt")
root_servers_IP = ["192.36.148.17", "192.58.128.30", "192.5.5.241"] 

# response that will be sent 
# when different errors occurs
def send_response_server_error(DNS_packet):
    DNS_error_response = DNS(
            id = DNS_packet[DNS].id,
            qr = 1,
            aa = 0,
            rcode = 2,                         # 2 = server couldn't handle the request
            qd = DNS_packet.qd
        )
    
    return DNS_error_response

def send_request_root_server(DNS_packet):
    # randomly choose one root server
    root_ip = IP(dst = random.choice(root_servers_IP))
    transport = UDP(dport = 53)

    # because root servers do not offer recursive lookups, 
    # set no recursion
    DNS_packet.rd = 0
    
    root_response = sr1(root_ip / transport / DNS_packet, verbose = 0, timeout = 2)

    if root_response is not None:
        # check if the response contains errors
        if root_response[DNS].rcode != 0:
            return root_response

        # there needs to be at least 2 additional records, because there is
        # a case when one and only one additional OPT record might be returned
        if root_response.arcount > 1:
            ar_cnt = randrange(root_response.arcount)

            while root_response.ar[ar_cnt].type != 1:
                ar_cnt = randrange(root_response.arcount)

            resp = root_response.ar[ar_cnt]

        else:
            # if there are not authority responses, check for
            # ns records that might help
            ns_cnt = randrange(root_response.nscount)
            resp = root_response.ns[ns_cnt]

            # request to the Google server in order
            # to find the IP address of the NS
            DNSRR_auth_query = DNSQR(qname = resp.rdata, qtype = 1, qclass = 1)
            DNSRR_auth_IP = sr1(IP(dst = '8.8.8.8') / UDP(dport = 53) / DNS(qd = DNSRR_auth_query, rd=1), verbose = 0, timeout = 2)
            resp = DNSRR_auth_IP[DNS].an

        return send_request_tld_server(DNS_packet, resp.rdata)
    else:
        # if there is no response from the TLD query,
        # send a server error response
        return send_response_server_error(DNS_packet)

def send_request_tld_server(DNS_packet, TLD_ip):
    TLD_IP = IP(dst = TLD_ip)
    transport = UDP(dport = 53)

    TLD_response = sr1(TLD_IP / transport / DNS_packet, verbose = 0, timeout = 2)

    if TLD_response is not None:
        # verify if the answer contains errors
        if TLD_response[DNS].rcode != 0:
            return TLD_response

        # verify if the TLD returned any answer
        if TLD_response.ancount > 0:
            return TLD_response

        # there needs to be at least 2 additional records, because there is
        # a case when one and only one additional OPT record might be returned
        elif TLD_response.arcount > 1:
            ar_cnt = randrange(TLD_response.arcount)

            while TLD_response.ar[ar_cnt].type != 1:
                ar_cnt = randrange(TLD_response.arcount)

            resp = TLD_response.ar[ar_cnt]
        else:
            # find the first NS record in the response, in order
            # to forward the request to that authoritative server
            ns_cnt = randrange(TLD_response.nscount)
            DNSRR_auth = TLD_response.ns[ns_cnt]

            # if it is a SOA record, that means it didn't find the desired record,
            # so this response needs to be returned
            if DNSRR_auth.type == 6:
                return TLD_response            

            # request to the Google server in order
            # to find the IP address of the NS
            DNSRR_auth_query = DNSQR(qname = DNSRR_auth.rdata, qtype = 1, qclass = 1)
            DNSRR_auth_IP = sr1(IP(dst = '8.8.8.8') / UDP(dport = 53) / DNS(qd = DNSRR_auth_query, rd=1), verbose = 0, timeout = 2)

            if DNSRR_auth_IP is None:
                return DNSRR_auth_IP
            
            resp = DNSRR_auth_IP[DNS].an

        # forward the request to the authoritative server
        return send_request_authoritative_server(DNS_packet, resp.rdata)
    else:
        return send_response_server_error(DNS_packet)


def send_request_authoritative_server(DNS_packet, authoritative_ip):
    auth_IP = IP(dst = authoritative_ip)
    transport = UDP(dport = 53)

    authoritative_resp = sr1(auth_IP / transport / DNS_packet, verbose = 0, timeout = 2)

    if authoritative_resp is not None:
        # if the request is not of time NS, but the response is,
        # it means that the request must be forwarded to that NS server 
        if DNS_packet.qd.qtype != 2 and authoritative_resp.nscount > 0 and authoritative_resp.an is None:
            # while the response contains NS records, not A / AAAA, ask Google's about the IP address of the NS,
            # than ask the NS for the desired domain
            while authoritative_resp is not None and authoritative_resp.nscount > 0 and authoritative_resp.ns.type == 2 and authoritative_resp.an is None:
                DNS_req = DNS(rd=1) # recursive search
                DNS_req_qd = DNSQR(qname=authoritative_resp.ns.rdata, qtype=1, qclass=1)  
                DNS_req.qd = DNS_req_qd 

                # fint the IP of the NS server
                authoritative_resp = sr1(IP(dst = '8.8.8.8') / UDP(dport = 53) / DNS_req, verbose = 0, timeout = 2)
                # find the desired records by asking the NS server
                authoritative_resp = sr1(IP(dst = authoritative_resp.an.rdata) / UDP(dport = 53) / DNS_packet[DNS], verbose = 0, timeout = 2)
                
        # if the request was of type A / AAAA, but the response is a CNAME,
        # recursively search for an IPv4 / IPv6 address instead of CNAMES
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

    # firstly check if the request domain is on the blacklist
    if domain_requested in adservers or domain_requested in facebook:
        # if indeed a black listed domain was requested, return an empty response
        # that will redirect to the '0.0.0.0'
        return get_ad_blocker_response(DNS_packet)

    response = send_request_root_server(DNS_packet)

    # if an answer was received, filter it
    if response is not None:
        DNS_response = response[DNS]
        DNS_response.id = DNS_packet[DNS].id    # response must have the initial query ID
        DNS_response.aa = 0                     # we are not the authoritative server:)
        DNS_response.qd = DNS_packet.qd         # response must have the initial query as 'qd' parameter

        return DNS_response
    
    else:
         # if no response was provided, return an error DNS response
        return send_response_server_error(DNS_packet)
    
def multiple_records_lookup(DNS_packet):
    domain_requested = DNS_packet.qd.qname.decode()[:-1]

    # firstly check if the request domain is on the blacklist
    if domain_requested in adservers or domain_requested in facebook:
        # if indeed a black listed domain was requested, return an empty response
        # that will redirect to the '0.0.0.0'
        return get_ad_blocker_response(DNS_packet)
    
    response = send_request_root_server(DNS_packet)

    if response is not None:
        DNS_response = response[DNS]
        DNS_response.id = DNS_packet[DNS].id    # raspunsul trebuie sa aiba ID-ului request-ului initial primit pe server-ul nostru
        DNS_response.aa = 0                     # nu putem spune ca suntem server-ul authoritative :)
        DNS_response.qd = DNS_packet.qd 

        # if the response is positive and contains answer records
        if DNS_response.rcode == 0 and DNS_response.ancount > 0:
            # for every answer in the NS request, we loop through the servers domain
            # and check if they are blacklisted or not
            for answer in range(DNS_response.ancount):
                NS_domain = DNS_response.an[answer].rdata.decode()[:-1] if DNS_packet.qd.qtype == 2 else DNS_response.an[answer].exchange.decode()[:-1]

                if NS_domain in adservers or NS_domain in facebook:
                    return get_ad_blocker_response(DNS_packet)

        return DNS_response
    
    else:
        return send_response_server_error(DNS_packet)