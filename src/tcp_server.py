print('TCP Server')
import socket
import logging
import time
from scapy.all import *

# send an ARP broadcast request to obtain the MAC address of the router
send(ARP(op=1, pdst="198.7.0.1", hwdst="ff:ff:ff:ff:ff:ff"))

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = '0.0.0.0' #localhost 
server_address = (adresa, port)
sock.bind(server_address)
logging.info("Serverul a pornit pe %s si portuls %d", adresa, port)

try:
    while True:

        # listen to requests
        sock.listen(5)
        logging.info('Asteptam conexiuni...')

        # accept the first connection which came and 
        # iniate the 3-way-handshake
        conexiune, address = sock.accept()
        logging.info("Handshake cu %s", address)

        while True:
            # server gets messages from the client
            data = conexiune.recv(1024)
            logging.info('SERVER: primit: %s', data)
            # server send a response to the client
            conexiune.send(b"Server a primit mesajul " + data)
                  
except KeyboardInterrupt:
    conexiune.close()
    sock.close()
    exit(0)

finally: sock.close()



