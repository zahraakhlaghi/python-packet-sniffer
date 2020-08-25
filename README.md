# python-packet-sniffer
In this project, I implemented a console-supervised program similar to Wireshark

To do this, you must first put the network card in the <b>promiscuous</b> mode so that you can see all types of packages.
This can be done with the following command in the Linux operating system

<h6>sudo ifconfig ens33 promisc #Enabling Promiscuous on ens33</h6>

<h6>sudo ifconfig ens33 -promisc #Disabling Promiscuous on ens33</h6>

The code saves the data in the form of <b>pcap</b> as soon as it is executed

ARP:
<image src = "https://raw.githubusercontent.com/zahraakhlaghi/python-packet-sniffer/master/images/arp.png"/>

ICMP:
<image src = "https://raw.githubusercontent.com/zahraakhlaghi/python-packet-sniffer/master/images/icmp.png"/>


TCP:
<image src = "https://github.com/zahraakhlaghi/python-packet-sniffer/blob/master/images/tcp.png?raw=true"/>

HTTP:
<image src = https://raw.githubusercontent.com/zahraakhlaghi/python-packet-sniffer/master/images/http.png"/>
                                                                                                          
UDP:
<image src = "https://raw.githubusercontent.com/zahraakhlaghi/python-packet-sniffer/master/images/udp.png"/>

DNS:
<image src = "https://raw.githubusercontent.com/zahraakhlaghi/python-packet-sniffer/master/images/dns.png"/>
                                                                                                          
