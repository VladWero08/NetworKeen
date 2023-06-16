def interpret_DNS_qtype(type):
    if type == 1:
        return "A"
    elif type == 2:
        return "NS"
    elif type == 5:
        return "CNAME"
    elif type == 15:
        return "MX"
    elif type == 28:
        return "AAAA"
    else:
        return "UNKNOWN"


def display_DNS_query(DNS_packet):
    domain_requested = DNS_packet.qd.qname.decode()[:-1]
    record_type = interpret_DNS_qtype(DNS_packet.qd.qtype)

    print("=========================")
    print("DNS request")
    print("=========================")
    print(f"| Request ID: {DNS_packet.id}")
    print(f"| Domain: {domain_requested}")
    print(f"| Record type: {record_type}")
    print("=========================")
    print()

def display_DNS_response(DNS_packet):
    print("=========================")
    print("DNS response")
    print("=========================")
    print(f"| Request ID: {DNS_packet.id}")
    print(f"| QR: {DNS_packet.qr}")
    print(f"| Operation code: {DNS_packet.opcode}")
    print(f"| Response code: {DNS_packet.rcode}")
    print(f"| QDcount: {DNS_packet.qdcount}")
    print(f"| ANcount: {DNS_packet.ancount}")
    print(f"| NScount: {DNS_packet.nscount}")
    print(f"| ARcount: {DNS_packet.arcount}")
        
    print("-------------------------")
    print("|| Questions: ")
    print("-------------------------")
    if DNS_packet.qd is not None:
        DNS_packet.qd.show()

    print("-------------------------")
    print("|| Answers: ")
    print("-------------------------")
    if DNS_packet.an is not None:
        DNS_packet.an.show()

    print("-------------------------")
    print("|| Authority: ")
    print("-------------------------")
    if DNS_packet.ns is not None:
        DNS_packet.ns.show()

    print("-------------------------")
    print("|| Additional: ")
    print("-------------------------")
    if DNS_packet.ar is not None:
        DNS_packet.ar.show()
    
    print("=========================")
    print()
