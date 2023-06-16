#Deriving the latest base image
FROM python:latest

RUN apt-get update && apt-get install -y iptables iproute2 libnetfilter-queue-dev net-tools tcpdump
RUN pip3 install scapy
RUN pip3 install --upgrade python-iptables cython

RUN mkdir -p /arp-spoof
COPY src/arp-spoof/*.py /arp-spoof/

RUN mkdir -p /scripts
COPY src/*.sh /scripts/
