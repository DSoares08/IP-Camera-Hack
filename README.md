# Tapo C200C Stream Corruption via Man-in-the-Middle (MITM) Attack

## Project Overview

The goal of this project is to demonstrate a network-level security flaw by executing a **Man-in-the-Middle (MITM) attack** on the TP-Link Tapo C200C camera's local video stream. We exploit the unencrypted nature of the **RTSP** (Real-Time Streaming Protocol) to capture, modify, and inject corrupted H.264 video packets in real-time. With this, the live video stream of the victim will be corrupted for a certain period of time, allowing for anything to happen without the camera's supervision.

* **Device:** TP-Link Tapo C200C Camera

## Methodology and Attack Strategy

### Bypassing Cloud Encryption

Initially, the stream works over the Internet via the **TP-Link Cloud**, meaning the traffic is protected by **TLS/SSL encryption**.

* **Problem:** Attacking the cloud stream requires complex methods like bypassing SSL Pinning, which is impractical for this project.
* **Our Solution:** We force the camera to use its local, unencrypted **RTSP stream** which is inherently unencrypted.



### Interception (ARP Spoofing)

* **IP Forwarding:** Enabled on the attacker machine so that unwanted packets are not automatically dropped.
* **The Deception:** Fake **ARP replies** are to be sent continuously:
    * To the **Camera** ($IP_{camera}$): Telling it the Client's IP is located at the Attacker's MAC ($\mathbf{MAC_{attacker}}$).
    * To the **Victim** ($IP_{client}$): Telling it the Camera's IP is located at the Attacker's MAC ($\mathbf{MAC_{attacker}}$).
* **Tunnel Established:** All unencrypted video traffic now flows: **Camera $\rightarrow$ Attacker $\rightarrow$ Victim.** This gives us the ability to view and control the flow of packets to the victims's stream.
* This shows the ARP Spoofing which is happening every 3 seconds : <img width="1141" height="39" alt="Screenshot 2025-12-05 at 12 23 29" src="https://github.com/user-attachments/assets/173ecbc1-41eb-4917-abb6-d5d13b7d21e4" />
* We also retrieved the source and destination ports on Wireshark using the following filter : udp and host 192.168.0.81 and host 192.168.0.162. This focuses only on video packets transmitted between the camera and victim. 


---

## Execution and Corruption Logic

The final step is the custom corruption script built with **Scapy**.

## Other research we didnt directly use for this attack
We have also analyzed requests made by the Tapo App, this was done by using the software "Burp Suite Community Edition".
You can enable "HTTP" proxy in BurpSuite. Within the wifi settings of your phone, you can then proxy every request your phone does towards your BurpSuite proxy on your laptop.
Then we installed the BurpSuite proxy root certificate and after trusting it within our phone, burpsuite can make all the https requests needed and act as a "MITM", so we can analyze all the https requests the app does, unencrypted.

It seems that your phone first sends out a login request to the camera, including a nonce called "cnonce". (192.168.0.81 is the camera's ip)
<img width="1239" height="262" alt="image" src="https://github.com/user-attachments/assets/c8ab3156-f563-4f4f-ad2c-a45a1c2532d7" />
Then the camera responds with another cnonce, a key and a device confirmation code.
<img width="1237" height="192" alt="image" src="https://github.com/user-attachments/assets/2c495549-00d8-4600-8c5b-32935ed7dc83" />
Then in the next request your camera does, it uses both the first nonce and second nonce, together with some other code as a prefix. We think this might be some hash that your app calculates based on the information given.
<img width="1233" height="265" alt="image" src="https://github.com/user-attachments/assets/e1135b8e-e93e-4d09-abd8-c68fc38bd145" />
If your camera accepts this request, it responds back with some "stok". This stok seems to be used all over as the only authentication in future requests.
<img width="982" height="151" alt="image" src="https://github.com/user-attachments/assets/203bf3e4-1a33-4705-ae02-67513549ae1f" />

See here a later request being made from the app to the camera. With just the app open and no other action.
<img width="1241" height="489" alt="image" src="https://github.com/user-attachments/assets/a56ab70d-aa2d-483c-a1d5-db668f62a9dd" />







