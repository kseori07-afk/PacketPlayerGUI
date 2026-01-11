from scapy.all import *

def load_pcap(filename):
    try:
        pkt_list = rdpcap(filename)
        return pkt_list
    except Exception as e:
        return None

def save_pcap(pkt_list, save_path):
    try:
        wrpcap(save_path, pkt_list)
        return True, f"{save_path} 에 저장 완료"
    except Exception as e:
        return False, str(e)