from scapy.all import *
from scapy.layers.inet import Ether, TCP, UDP, IP, ICMP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

def modify_MAC(pkt, type, new_mac):
    if not pkt.haslayer(Ether):
        return pkt
    if type == 'src':
        pkt[Ether].src = new_mac
    elif type == 'dst':
        pkt[Ether].dst = new_mac
    return pkt

def modify_IP(pkt, type, new_IP):
    if not pkt.haslayer(IP):
        return pkt
    if type == 'src':
        pkt[IP].src = new_IP
    elif type == 'dst':
        pkt[IP].dst = new_IP

    if 'chksum' in pkt[IP].fields:
        del pkt[IP].chksum
    if 'len' in pkt[IP].fields:
        del pkt[IP].len
    if pkt.haslayer(Ether):
        pkt = Ether(raw(pkt))
    return pkt

def modify_Port(pkt, type, new_port):
    ############# TCP 헤더 변조 #############
    try:
        new_port = int(new_port)
    except:
        return pkt

    if pkt.haslayer(TCP):
        if type == 'src':
            pkt[TCP].sport = new_port
        elif type == 'dst':
            pkt[IP].dport = new_port
        if 'chksum' in pkt[TCP].fields:
            del pkt[TCP].chksum
        if 'len' in pkt[TCP].fields:
            del pkt[TCP].len
    ############# UDP 헤더 변조 #############
    elif pkt.haslayer(UDP):
        if type == 'src':
            pkt[UDP].sport = new_port
        elif type == 'dst':
            pkt[UDP].dport = new_port
        if 'chksum' in pkt[UDP].fields:
            del pkt[UDP].chksum
        if 'len' in pkt[UDP].fields:
            del pkt[UDP].len
    else:
        return pkt

    if pkt.haslayer(Ether):
        pkt = Ether(raw(pkt))
    return pkt

def modify_HTTP(pkt, field_type, new_value):
    if not pkt.haslayer(HTTP):
        if pkt.haslayer(TCP) and (pkt[TCP].sport==80 or pkt[TCP].dport==80):
            try:
                pkt[TCP].payload = HTTP(pkt[TCP].payload.load)
            except:
                return pkt
    if isinstance(new_value, str):
        new_val_bytes = new_value.encode()
    else:
        new_val_bytes = new_value
    ##################################### HTTP Request 변조 #####################################
    if pkt.haslayer(HTTPRequest):
        if field_type == 'Method':
            pkt[HTTPRequest].Method = new_val_bytes
        elif field_type == "Host":
            pkt[HTTPRequest].Host = new_val_bytes
        elif field_type == 'Path':
            pkt[HTTPRequest].Path = new_val_bytes
        elif field_type == "User-Agent":
            pkt[HTTPRequest].User_Agent = new_val_bytes
    ##################################### HTTP Response 변조 #####################################
    if pkt.haslayer(HTTPResponse):
        if field_type == 'Status Code':
            pkt[HTTPResponse].Status_Code = new_val_bytes
        elif field_type == "Reason Phrase":
            pkt[HTTPResponse].Reason_Phrase = new_val_bytes
    ##################################### 체크섬 재계산 #####################################
    if pkt.haslayer(IP):
        del pkt[IP].len
        del pkt[IP].chksum
    if pkt.haslayer(TCP):
        del pkt[TCP].chksum
    if pkt.haslayer(Ether):
        pkt = Ether(raw(pkt))
    return pkt
