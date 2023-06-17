from flask import Flask, jsonify
from flask import request
import requests
from scapy.all import *
import socket

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello World!"

@app.route('/post', methods=['POST'])
def post_method():
    print("Got from user: ", request.get_json())
    requestedDomain = request.get_json()['value']
    
    # DNS request to your DNS server
    ip = IP(dst='198.8.0.3')  # Replace with the IP address of your DNS server
    transport = UDP(dport=53)  # Replace with the port number of your DNS server

    # rd = 1 cod de request
    dns = DNS(rd=1)

    # query pentru a afla entry de tipul 
    dns_query = DNSQR(qname=requestedDomain, qtype=1, qclass=1)
    dns.qd = dns_query

    answer = sr1(ip / transport / dns)

    return jsonify({'got_it': answer[DNS].summary()})

@app.route('/<name>')
def hello_name(name):
    return "Hello {}!".format(name)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8001)
