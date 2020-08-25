import protocol
import socket
import textwrap
from pcap import Pcap

def format_multi_line(prefix, String, size=80):
    size -= len(prefix)
    if isinstance(String, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in String)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


""""------------------DEF main------------------"""

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    pcap = Pcap('capture.pcap')
    k=1
    while True:
        print('\n\n\t\t\t----------\t'+str(k)+'\t----------\n\n')
        k=k+1
        raw_data, addr = s.recvfrom(65535)
        pcap.write(raw_data)
        eth = protocol.Ethernet()
        proto, ether_data = eth.eternet_header(raw_data)
        if int(proto) == 8:
            ipv4 = protocol.IPv4()
            proto_port, ipv4_data = ipv4.ipv4_header(ether_data)

            if int(proto_port) == 6:
                tcp = protocol.TCP()
                s_port, d_port, tcp_data = tcp.tcp_header(ipv4_data)
                if len(tcp_data) > 0:
                    if int(s_port) == 80 or int(d_port) == 80:
                        try:
                            http = protocol.HTTP()
                            http_data = http.http_header(tcp_data)
                            http_info = str(http_data).split('\n')
                            for line in http_info:
                                print(protocol.STRING_THREE_TAB + str(line))
                        except:
                            print(format_multi_line(protocol.STRING_THREE_TAB ,tcp_data))
                    else:
                        print(protocol.STRING_TWO_TAB + '- TCP Data:')
                        print(format_multi_line(protocol.STRING_THREE_TAB ,tcp_data))


            elif int(proto_port) == 17:
                udp = protocol.UDP()
                s_port,d_port,udp_data = udp.udp_header(ipv4_data)
                if len(udp_data) > 0:
                    if int(s_port) == 53 or int(d_port) == 53:
                        try:
                            dns = protocol.DNS()
                            dns_data = dns.dns_header(udp_data)
                            print(protocol.STRING_THREE_TAB+'DNS Data: ')
                            dns_info = str(dns_data).split('\n')
                            for line in dns_info:
                                print(protocol.STRING_THREE_TAB + str(line))
                        except:
                            print(format_multi_line(protocol.STRING_THREE_TAB,udp_data))

                    else:
                        print(protocol.STRING_TWO_TAB + "- UDP Data:")
                        print(format_multi_line(protocol.STRING_THREE_TAB ,udp_data))


            elif int(proto_port) == 1:

                icmp = protocol.ICMP()
                icmp_data = icmp.icmp_header(ipv4_data)
                print(protocol.STRING_TWO_TAB + "- ICMP Data:")
                print(format_multi_line(protocol.STRING_THREE_TAB,icmp_data))

            else:

                print(protocol.STRING_TWO_TAB + "- Other IPv4 Data:")
                print(format_multi_line(protocol.STRING_THREE_TAB ,ipv4_data))

        elif int(proto) == 1544:
            arp=protocol.ARP()
            arp_data=arp.arp_header(ether_data)


        else:
            if ether_data:
              print(protocol.STRING_ONE_TAB+'- Ethernet Data:')
              print(format_multi_line(protocol.STRING_TWO_TAB,ether_data))



    pcap.close()

"""------------------END main------------------"""

main()
