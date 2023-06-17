# NetworKeen
Not only that this project is aimed to rebuild some networking utilities( traceroute, DNS ad blocker server) but also to simulate some cyber-attacks related to networking( ARP spoofing, TCP Hijacking). It is mostly built with the help of <a href="https://scapy.net/">scapy</a> and other API/Python libraries. 
I have worked alongside my amigo <a href="https://github.com/Iradu15">Radu</a>. :) 

## 🗺️ Traceroute 
Traceroute will send a UDP message with increasing values of TTL until the final destination is reached. For each IP encountered, pieces of information about its geographical location will be stored inside a dictionary and eventually displayed a map of countries encountered during the transmission of the message. Depending on the location where the code was executed, some routes as been saved inside _./src/traceroute-utilities/locations.txt_.

## ✋ DNS ad blocked server 
Using this <a href="https://github.com/anudeepND/blacklist">blacklist</a>, we have built a DNS adblocker server. Whenever one domain from the list is requested, the server will redirect the request to **'0.0.0.0 / ::**. Each blocked domain is stored in the file: _./src/dns-ad-blocker/blacklists/blocked_domains.txt_, and using that information a statistic can be generated to discover which domains were the most blocked.

The server runs on a **docker-compose orchestration**, on the container with the IP = **198.8.0.3**. 

## Structure of the containers
For the ARP spoofing and TCP hijacking, we used a docker-compose orchestration in which we will simulate the attacks. For each attack, it will be a different orchestration, but the structure of the containers will be the same:

```
            MIDDLE------------\
        subnet2: 198.7.0.3     \
        MAC: 02:42:c6:0a:00:02  \
               forwarding        \ 
              /                   \
             /                     \
Poison ARP 198.7.0.1 is-at         Poison ARP 198.7.0.2 is-at 
           02:42:c6:0a:00:02         |         02:42:c6:0a:00:02
           /                         |
          /                          |
         /                           |
        /                            |
    SERVER <---------------------> ROUTER <---------------------> CLIENT
net2: 198.7.0.2                      |                           net1: 172.7.0.2
MAC: 02:42:c6:0a:00:03               |                            MAC eth0: 02:42:ac:0a:00:02
                           subnet1:  172.7.0.1
                           MAC eth0: 02:42:ac:0a:00:01
                           subnet2:  198.7.0.1
                           MAC eth1: 02:42:c6:0a:00:01
                           subnet1 <------> subnet2
                                 forwarding
```

## 🕵️‍♂️ ARP Spoofing
Initially, each container executes a shell script that will configure the routes. Client & server set the **router as the default gateway**, canceling the default gateway set by docker. Middle sets **ip_forwarding=1** and the rule _iptables -t nat -A POSTROUTING -j MASQUERADE_ , so that the messages are able to be forwarded outside the local network.

The router and server need to learn each other's MAC address. Afterward, the middle container will **continuously send ARP replies** to the server & router, in order to modify their ARP table. In the middle container, the communication between the server and router can be intercepted.

## 🕵️‍♂️ TCP Hijacking
On one hand, the server will be running _"tcp_server.py"_ script, on the other hand, the client will be running _"tcp_client.py"_. They will send messages to each other continuously ( time.sleep() will be used to prevent flooding). Using ARP spoofing, get the middle between the 'conversation' of server and client. After the middle container starts to intercept the messages, those messages will be modified and sent as if _the communication is taking place in normal conditions_.
