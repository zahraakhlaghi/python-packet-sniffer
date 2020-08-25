import socket
import struct
import binascii

STRING_ONE_TAB="\t"
STRING_TWO_TAB="\t\t"
STRING_THREE_TAB="\t\t\t"


def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr

class Ethernet():
    """class for separate ethernet frame"""

    def eternet_header(self,data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        dectination_mac = get_mac_addr(dest_mac)
        source_mac = get_mac_addr(src_mac)
        prtocol = socket.htons(proto)
        print(
            STRING_ONE_TAB + '- Destination: {}, Source: {}, Type: {}'.format(dectination_mac, source_mac, prtocol))

        return prtocol,data[14:]
    def __init__(self):
        print("- Ethernet Frame:")


class IPv4():
     """"class for separate header ip"""

     def get_ip(self,addr):
         return '.'.join(map(str, addr))

     def ipv4_header(self,data):
         version_header_length = data[0]
         version = version_header_length >> 4
         header_length = (version_header_length & 15) * 4
         ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
         src=self.get_ip(src)
         target=self.get_ip(target)
         raw_data = data[header_length:]
         print(STRING_TWO_TAB + '- Version: {}, Header Length: {}, TTL:{}, '.format(version, header_length, ttl))
         print(STRING_TWO_TAB + '- Protocol: {}, Source: {}, Destination: {}'.format(proto, src, target))
         return proto,raw_data
     def __init__(self):
         print(STRING_ONE_TAB+"- IPv4 packet:")

class ARP():
    """class for protocol arp"""
    def __init__(self):
        print(STRING_ONE_TAB + "- ARP packet:")

    def get_ip(self, addr):
        return '.'.join(map(str, addr))

    def arp_header(self,data):
        (a, b, c, d, e, f, g, h, i) = struct.unpack('2sH1s1s2s6s4s6s4s', data[:42])

        hw_type = (binascii.hexlify(a)).decode('utf-8')
        hw_size = (binascii.hexlify(c)).decode('utf-8')
        proto_size = (binascii.hexlify(d)).decode('utf-8')
        opcode = (binascii.hexlify(e)).decode('utf-8')
        dectination_mac = get_mac_addr(h)
        source_mac = get_mac_addr(f)
        print(STRING_TWO_TAB+'- Hardware type: {}, Protocol type: {}'.format(int(hw_type),b))
        print(STRING_TWO_TAB+'- Hardware address length: {}, Protocol address length: {},Operation: {}'.format(int(hw_size),int(proto_size),int(opcode)))
        print(STRING_TWO_TAB+'- Sensder Mac Address:{}, Sender IP Address: {}'.format(source_mac,socket.inet_ntoa(g)))
        print(STRING_TWO_TAB +'- Target Mac Address:{}, Target IP Address: {}'.format(dectination_mac,socket.inet_ntoa(i)))


        return data[42:]


class TCP():
     """class for separate header tcp"""
     def tcp_header(self,data):
         src_port, dest_port, sequence, acknowledgment, offset_reserved_flags,widows_size,check_sum,pointer =struct.unpack('! H H L L H H H H', data[:20])
         checksum = hex(check_sum)
         offset = (offset_reserved_flags >> 12) * 4
         urg = (offset_reserved_flags & 32) >> 5
         ack = (offset_reserved_flags & 16) >> 4
         psh = (offset_reserved_flags & 8) >> 3
         rst = (offset_reserved_flags & 4) >> 2
         syn = (offset_reserved_flags & 2) >> 1
         fin = offset_reserved_flags & 1
         raw_data = data[offset:]
         print(STRING_TWO_TAB+ '- Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
         print(STRING_TWO_TAB+ '- Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
         print(STRING_TWO_TAB+ '- Flags:')
         print(STRING_THREE_TAB+ '- URG: {}, ACK: {}, PSH: {}'.format(urg, ack, psh))
         print(STRING_THREE_TAB + '- RST: {}, SYN: {}, FIN: {}'.format(rst, syn, fin))
         print(STRING_TWO_TAB + '- Windows Size: {}, Checksum: {}, Upgrade Pointer: {}'.format(widows_size, checksum, pointer))
         return src_port,dest_port,raw_data
     def __init__(self):
         print(STRING_ONE_TAB+ '- TCP Segment:')


class  ICMP():
    """class for separate icmp protocol"""
    def icmp_header(self,data):
        type, code, checksum = struct.unpack('!BBH', data[:4])
        checksum=hex(checksum)
        print(STRING_TWO_TAB+'- Type: {}, Code: {}, Checksum: {}'.format(type,code,str(checksum)))
        return data[4:]
    def __init__(self):
        print(STRING_ONE_TAB+'- ICMP Segment:')

class UDP():
    """class for separate udp segment"""
    def udp_header(self,data):
        src_port, dest_port,length=struct.unpack('! H H 2x H', data[:8])
        lenhed=length & 0xF
        print(STRING_TWO_TAB+'- Source Port: {}, Destination Port: {}, Length:{}'.format(src_port,dest_port, str(lenhed)))
        return src_port,dest_port,data[8:]
    def __init__(self):
        print(STRING_ONE_TAB+"- UDP Segment")

class HTTP():
   """class for protocol http"""
   def http_header(self,data):
       try:
           raw_data = data.decode('utf-8')
       except:
           raw_data = data

       return raw_data

   def __init__(self):
       print(STRING_TWO_TAB+"- HTTP Data:")


class DNS():
   """class for dns protocol"""

   def dns_header(self,data):
     t_id,flag,num_question,num_answer,num_authoritative,num_additional = struct.unpack('! H H H H H H',data[:12])
     print(STRING_THREE_TAB+'- Transaction ID: {},Flags: {}'.format(str(t_id),str(flag)))
     print(STRING_THREE_TAB+'- Questions: {},Answer RRs: {},Authority RRs: {},Additional RRs: {}'
           .format(num_question,num_answer,num_authoritative,num_additional))
     data=data[12:]
     try:
         raw_data = data.decode('utf-8')
     except:
         raw_data = data

     return raw_data

   def __init__(self):
       print(STRING_TWO_TAB+"- DNS Header: ")
