from scapy.all import sendp, conf

def get_interfaces():
    iface_list = []
    for iface in conf.ifaces.data.values():
        name = iface.name
        desc = iface.description if iface.description else name
        mac = iface.mac if iface.mac else None
        ip = iface.ip if iface.ip else None
        iface_list.append((name, desc))
    return iface_list

########## 단일 패킷 전송 ##########
def send_packet(pkt, iface_name, count=1):
    try:
        sendp(pkt, iface=iface_name, count = count, verbose=True)
        return True, "성공"
    except Exception as e:
        return False, str(e)

########## 여러 패킷 전송 ##########
def relay_packet(relay_list, iface_name, count=1):
    try:
        sendp(relay_list, iface=iface_name, count=count, verbose=False)
        return True, f"{len(relay_list)} 개 패킷 전송"
    except Exception as e:
        return False, str(e)
