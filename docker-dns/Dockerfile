#Deriving the latest base image
FROM python:latest

#Labels as key value pair
LABEL Maintainer="radu"

# Any working directory can be chosen as per choice like '/' or '/home' etc
# i have chosen /usr/app/src

COPY ./ ./
RUN apt-get update && apt-get install -y dnsutils
RUN pip install flask scapy requests
