print('TCP Server')
import socket
import logging
import time
from scapy.all import *

# ping(ARP request pe broadcast) necesar ca router-ul sa aibe server-ul in tabela lui ARP 
send(ARP(op=1, pdst="198.7.0.1", hwdst="ff:ff:ff:ff:ff:ff"))


logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

#server-ul se deschide pe 0.0.0.0 port 10000
port = 10000
adresa = '0.0.0.0' #localhost 
server_address = (adresa, port)
sock.bind(server_address)
logging.info("Serverul a pornit pe %s si portuls %d", adresa, port)

try:
    while True:
        #se asculta cereri de conexiune
        sock.listen(5)
        logging.info('Asteptam conexiuni...')
        #se accepta prima conexine venita si se initiaza handshake-ul
        conexiune, address = sock.accept()
        logging.info("Handshake cu %s", address)

        while True:
            #server-ul primeste de la client
            data = conexiune.recv(1024)
            logging.info('SERVER: primit: %s', data)
            #server-ul trimite inapoi la client un mesaj
            conexiune.send(b"Server a primit mesajul " + data)
                  
except KeyboardInterrupt:
    conexiune.close()
    sock.close()
    exit(0)

finally: sock.close()



