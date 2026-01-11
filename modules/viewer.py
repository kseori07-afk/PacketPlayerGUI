from PyQt6.QtWidgets import QTableWidget
from scapy.all import *
from scapy.layers.inet import TCP, UDP, IP, ICMP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from datetime import datetime

from scapy.layers.l2 import Ether


def pcapViewer(i, pkt):
    ########## QTableWidget에 넣을 한 줄 요약 데이터 반환 ##########
    num = str(i+1)
    try:
        timestamp = datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S')
    except:
        timestamp = "00-00-00 00:00:00"

    srcip = "-"
    dstip = "-"
    protocol = "Other"
    length = str(len(pkt))
    info = ""

    ########## IP 레이어 처리 ##########
    if pkt.haslayer(IP):
        srcip = pkt[IP].src
        dstip = pkt[IP].dst
        proto_num = pkt[IP].proto
        if proto_num == 6: protocol = "TCP"
        elif proto_num == 17: protocol = "UDP"
        elif proto_num == 8: protocol = "ICMP"

    ########## 전송 계층 + ICMP 처리 ##########
    if pkt.haslayer(TCP):
        info = f"{pkt[TCP].sport} -> {pkt[TCP].dport} [{pkt[TCP].flags}]"
    elif pkt.haslayer(UDP):
        info = f"{pkt[UDP].sport} -> {pkt[UDP].dport}"
    elif pkt.haslayer(ICMP):
        info = f"Type: {pkt[ICMP].code} {pkt[ICMP].code}"
    elif pkt.haslayer(HTTPRequest):
        protocol = "HTTP"
        info = f"{pkt[HTTPRequest].method.decode()} {pkt[HTTPRequest].path.decode()}"
    elif pkt.haslayer(HTTPResponse):
        protocol = "HTTP"
        info = f"{pkt[HTTPResponse].Status_Code.decode()} {pkt[HTTPResponse].Reason_Phrase.decode()}"
    ########## 반환 ##########
    return (num, timestamp, srcip, dstip, protocol, length, info)

def packetViewer(pkt):
    lines = []
    lines.append("===============================")
    if pkt.haslayer(Ether):
        lines.append(f"source MAC: {pkt[Ether].src}")
        lines.append(f"destination MAC: {pkt[Ether].dst}")
        lines.append("===============================")
    if pkt.haslayer(IP):
        lines.append(f"source IP: {pkt[IP].src}")
        lines.append(f"destination IP: {pkt[IP].dst}")
        lines.append("===============================")
    if pkt.haslayer(TCP):
        lines.append(f"Protocol: TCP")
        lines.append(f"source port: {pkt[TCP].sport}")
        lines.append(f"destination port: {pkt[TCP].dport}")
        lines.append(f"flags: {pkt[TCP].flags}")
    elif pkt.haslayer(UDP):
        lines.append(f"Protocol: UDP")
        lines.append(f"source port:{pkt[UDP].sport}")
        lines.append(f"destination port:{pkt[UDP].dport}")

    if pkt.haslayer(HTTPRequest):
        lines.append("======== HTTP Request Info ========")
        try:
            method = pkt[HTTPRequest].Method.decode() if pkt[HTTPRequest].Method else "-"
            host = pkt[HTTPRequest].Host.decode() if pkt[HTTPRequest].Host else "-"
            path = pkt[HTTPRequest].Path.decode() if pkt[HTTPRequest].Path else "-"
            ua = pkt[HTTPRequest].User_Agent
            ua = ua.decode() if ua else "-"
            lines.append(f"Method : {method}")
            lines.append(f"Host   : {host}")
            lines.append(f"Path   : {path}")
            lines.append(f"Agent  : {ua}")
        except:
            lines.append("(Decode Error)")

    elif pkt.haslayer(HTTPResponse):
        lines.append("======== HTTP Response Info =======")
        try:
            code = pkt[HTTPResponse].Status_Code.decode() if pkt[HTTPResponse].Status_Code else "-"
            reason = pkt[HTTPResponse].Reason_Phrase.decode() if pkt[HTTPResponse].Reason_Phrase else "-"
            lines.append(f"Response Code: {code}")
            lines.append(f"Response Reason: {reason}")
        except:
            lines.append("(Decode Error)")
    elif pkt.haslayer(ICMP):
        print("ICMP")
        print(f"Type : {pkt[ICMP].type}")
        print(f"Code : {pkt[ICMP].code}")

    elif pkt.haslayer(Raw):
        lines.append("======== Raw Payload =======")
        lines.append(str(pkt[Raw].load))
    return "\n".join(lines)



