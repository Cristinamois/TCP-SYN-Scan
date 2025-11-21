import socket
import struct
import sys
import random

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

#Connect Scan simple
def scan_ports(target, port):
    print(f"[+] Connect scan sur {target}:{port}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((target, port))
        print(f"[*] Port open : " + str(port))
        s.close()
    except:
        print(f"[-] Port closed : " + str(port))


def syn_scan(target, port):
    print(f"[+] SYN scan RAW sur {target}:{port}")

    source_ip = '192.168.0.27'
    dest_ip = target

    src_port = random.randint(49152, 65535)
    seq = random.randint(0, 0xFFFFFFFF)

    #IP HEADER

    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0 #Kernel s'en occupe
    ip_id = random.randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header_wo_checksum = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, 0, ip_saddr, ip_daddr)
    ip_check = checksum(ip_header_wo_checksum)

    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)



    #TCP HEADER
    ack_seq = 0
    data_offset = 5 << 4
    flags = 0x02 #SYN
    window = 64240
    check = 0
    urg_ptr = 0

    tcp_header = struct.pack(
        '!HHLLBBHHH',
        src_port,
        port,
        seq,
        ack_seq,
        data_offset,
        flags,
        window,
        check,
        urg_ptr
    )

    #pseudo Header
    pseudo_header = struct.pack(
        '!4s4sBBH',
        ip_saddr,
        ip_daddr,
        0,
        socket.IPPROTO_TCP,
        len(tcp_header)
    )

    tcp_checksum = checksum(pseudo_header + tcp_header)

    tcp_header = struct.pack(
        '!HHLLBBHHH',
        src_port,
        port,
        seq,
        ack_seq,
        data_offset,
        flags,
        window,
        tcp_checksum,
        urg_ptr
    )

    packet = ip_header + tcp_header

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        print("Port open : " + str(port))
    except socket.error as msg:
        print("Socket could not be created. Error Code : " + str(msg[0]) + ' Message ' + str(msg[1]))
        sys.exit()

    s.sendto(packet, (dest_ip, 0))

    print("[*] SYN sent. Check Wireshark.")


def menu():
    print("\n===================\n     KaliScanny\n===================\n\n1) Connect Scan (TCP Classique)\n2) SYN Scan (RAW)\n3) Exit\n")

    choice = input("Votre choix : ")
    if choice == "1":
        target = input("Cible : ")
        port = int(input("Port : "))
        scan_ports(target, port)
    elif choice == "2":
        target = input("Cible : ")
        port = int(input("Port : "))
        syn_scan(target, port)
    elif choice == "3":
        print("Bye.")
        return False
    else:
        print("Choix invalide.")
        return True

if __name__ == "__main__":
    while menu():
        pass
