import socket
import struct
import sys

#Fonction checksum

def checksum(data):
    if len(data) % 2 == 1:
        data += b'\x00'

    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w

    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)

    return ~s & 0xffff


#creer socket ici

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
except socket.error as msg:
    print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + str(msg[1]))
    sys.exit()

source_ip = '192.168.x.x' #Changer par adresse IP source
dest_ip = '192.168.x.x'   #Same pour dest

#IP HEADER

ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tot_len = 0 #Kernel s'en occupe
ip_id = 54321
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_TCP
ip_check = 0
ip_saddr = socket.inet_aton(source_ip)
ip_daddr = socket.inet_aton(dest_ip)

ip_ihl_ver = (ip_ver << 4) + ip_ihl

ip_header_wo_checksum = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, 0, ip_saddr, ip_daddr)
ip_check = checksum(ip_header_wo_checksum)

ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)


#TCP HEADER

tcp_length = 20

pseudo_header = struct.pack('!4s4sBBH', ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, tcp_length)

tcp_source = 12345    #PEnser a bien ouvrir hein.
tcp_dest = 12345
tcp_seq = 454
tcp_ack_seq = 0
tcp_doff = 5

tcp_fin = 0
tcp_syn = 1
tcp_rst = 0
tcp_psh = 0
tcp_ack = 0
tcp_urg = 0
tcp_window = socket.htons (5840)
tcp_check = 0
tcp_urg_ptr = 0

tcp_offset_res = (tcp_doff << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

tcp_header_wo_checksum = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, 0, tcp_urg_ptr)
tcp_check = checksum(pseudo_header + tcp_header_wo_checksum)

tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

packet = ip_header + tcp_header

s.sendto(packet, (dest_ip, 0))
