from scapy.all import sniff, UDP, IP, RTP
import struct
import subprocess
import sys
import os
import threading
import time
from collections import defaultdict

IFACE = "en0"
IP_CAMERA = "192.168.0.81"
IP_CLIENT = "192.168.0.162"

h264_buffer = bytearray()
packet_count = 0
video_packet_count = 0
ffplay_process = None
seen_pt = set()

sps_pps_written = False
sps_data = None
pps_data = None
idr_written = False

frag_buffer = {}
last_seq = None

write_buffer = bytearray()
last_flush = time.time()

def get_nal_type(nal_unit):
    """Extract NAL unit type from first byte"""
    if len(nal_unit) < 1:
        return None
    return nal_unit[0] & 0x1F

def write_nal_unit(nal_unit):
    """Write a NAL unit to ffplay pipe"""
    global sps_pps_written, sps_data, pps_data, ffplay_process

    if not ffplay_process or not ffplay_process.stdin:
        return

    try:
        if not sps_pps_written and sps_data and pps_data:
            ffplay_process.stdin.write(sps_data)
            ffplay_process.stdin.write(pps_data)
            ffplay_process.stdin.flush()
            sps_pps_written = True
            print("[+] Wrote SPS/PPS to stream!")

        if sps_pps_written:
            nal_with_start = b'\x00\x00\x00\x01' + nal_unit
            ffplay_process.stdin.write(nal_with_start)
            ffplay_process.stdin.flush()
    except (BrokenPipeError, IOError):
        pass

def process_packet(pkt):
    global h264_buffer, packet_count, video_packet_count, seen_pt
    global sps_data, pps_data, idr_written, frag_buffer, last_seq

    if UDP not in pkt or IP not in pkt:
        return
    if pkt[IP].src != IP_CAMERA or pkt[IP].dst != IP_CLIENT:
        return

    packet_count += 1

    try:
        payload = bytes(pkt[UDP].payload)
        if len(payload) < 12:
            return

        pt = payload[1] & 0x7F
        seq = struct.unpack("!H", payload[2:4])[0]

        if packet_count % 500 == 0:
            print(f"[*] Packets: {packet_count}, Video: {video_packet_count}")

        video_packet_count += 1
        rtp_payload = payload[12:]
        if len(rtp_payload) < 1:
            return

        nal_unit = None
        nal_type_indicator = rtp_payload[0] & 0x1F

        if nal_type_indicator == 28:  
            if len(rtp_payload) < 2:
                return
            fu_header = rtp_payload[1]
            s_bit = (fu_header >> 7) & 0x01
            e_bit = (fu_header >> 6) & 0x01
            nal_type_frag = fu_header & 0x1F

            if s_bit:
                h264_buffer = bytearray([(rtp_payload[0] & 0xE0) | nal_type_frag])
                h264_buffer.extend(rtp_payload[2:])
            elif len(h264_buffer) > 0:
                h264_buffer.extend(rtp_payload[2:])

            if e_bit and len(h264_buffer) > 0:
                nal_unit = bytes(h264_buffer)
                h264_buffer = bytearray()
        elif nal_type_indicator == 24:  
            return
        elif nal_type_indicator > 0 and nal_type_indicator < 24:
            nal_unit = rtp_payload

        if not nal_unit:
            return

        nal_type = get_nal_type(nal_unit)

        if nal_type == 7:  
            sps_data = b'\x00\x00\x00\x01' + nal_unit
            print(f"[+] Captured SPS!")
        elif nal_type == 8:  
            pps_data = b'\x00\x00\x00\x01' + nal_unit
            print(f"[+] Captured PPS!")
        elif nal_type == 5:  
            if not idr_written:
                print("[+] Captured first IDR frame!")
                idr_written = True

        write_nal_unit(nal_unit)

    except Exception as e:
        if packet_count % 500 == 0:
            print(f"[!] Error: {e}")

def start_player():
    """Start ffplay with pipe input for real-time streaming"""
    global ffplay_process

    print("[*] Waiting for SPS/PPS headers...")

    for i in range(30):
        time.sleep(0.5)
        if sps_data and pps_data:
            print("[+] SPS/PPS received, starting player...")
            break
        if i % 4 == 0:
            print(f"[*] Still waiting for video headers... ({i//2}s)")

    if not (sps_data and pps_data):
        print("[!] Timeout waiting for SPS/PPS")
        return

    try:
        ffplay_process = subprocess.Popen(
            ['ffplay',
             '-f', 'h264',           
             '-fflags', 'nobuffer',   
             '-flags', 'low_delay',   
             '-probesize', '32',      
             '-analyzeduration', '0',
             '-sync', 'video',       
             '-framedrop',           
             '-vf', 'setpts=N/30/TB',
             '-window_title', 'Camera Feed - Live',
             '-'],                   
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("[+] ffplay started with pipe streaming!")
    except FileNotFoundError:
        print("[!] ffplay not found. Install with: brew install ffmpeg")
        ffplay_process = None

if __name__ == "__main__":
    print("[*] Starting camera viewer...")
    print("[*] Capturing packets from camera stream...")

    player_thread = threading.Thread(target=start_player, daemon=True)
    player_thread.start()

    try:
        sniff(
            iface=IFACE,
            filter=f"udp and src {IP_CAMERA} and dst {IP_CLIENT}",
            prn=process_packet,
            store=False,  
            timeout=None  
        )
    except KeyboardInterrupt:
        print("\n[*] Stopping viewer...")
    finally:
        print(f"\n[*] Summary:")
        print(f"    Total packets: {packet_count}")
        print(f"    Video packets: {video_packet_count}")
        print(f"    SPS/PPS written: {sps_pps_written}")
        if ffplay_process:
            try:
                ffplay_process.stdin.close()
                ffplay_process.terminate()
                ffplay_process.wait(timeout=2)
            except:
                pass