print('TCP client')
import socket
import logging
import time
import sys

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = '198.7.0.2'
server_address = (adresa, port)
mesaj = 'blup'#sys.argv[1]
logging.info('Mesaj pe care il vom trimite %s', mesaj)


try:
    time.sleep(2)
    # clientul se conecteaza la server, iar 3-way-handshake-ul este initiat (SYN, SYN-ACK, ACK)
    sock.connect(server_address)
    logging.info('Handshake reusit cu %s', str(server_address))
    while True:
        time.sleep(6)
        #clientul trimite mesaj server-ului
        sock.send(mesaj.encode('utf-8'))
        logging.info('CLIENT: Tocmai s-a trimis mesajul catre server(sper):')
        #clientul printeaza ce primeste de la server
        data = sock.recv(1024)
        logging.info('CLIENT: Reply primit: "%s"', data.decode('utf-8'))


except KeyboardInterrupt:
    logging.info('closing socket')
    sock.close()

finally:
    logging.info('closing socket')
    sock.close()



