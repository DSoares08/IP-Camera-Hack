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


---

## Execution and Corruption Logic

The final step is the custom corruption script built with **Scapy**.
