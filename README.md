# MAVLink-Proxy-Encryption-Layer
Lightweight UDP proxy that adds ChaCha20-Poly1305 encryption to MAVLink traffic between SITL and Mission Planner.

This project implements a lightweight UDP proxy that adds authenticated encryption to MAVLink telemetry traffic using ChaCha20-Poly1305.

It is designed for a simulated drone environment using ArduPilot SITL and Mission Planner.

## Overview

MAVLink communication is typically sent in plaintext, making it vulnerable to interception or tampering. This project introduces an encryption layer that:

- Encrypts MAVLink packets on the sender side (Pi)
- Decrypts packets on the receiver side (Windows)
- Preserves real-time UDP communication

This allows secure telemetry transmission without modifying MAVLink itself.

## Features

- UDP-based proxy for real-time MAVLink traffic  
- Authenticated encryption using ChaCha20-Poly1305 (AEAD)  
- Per-packet random nonce generation  
- Integrity verification (tampering detection)  
- Lightweight and easy to deploy  

## How It Works

Each MAVLink packet is:
1. Received as plaintext  
2. Encrypted using ChaCha20-Poly1305  
3. Prepended with a 12-byte nonce  
4. Sent over UDP  

On the receiving side:
1. Nonce is extracted  
2. Ciphertext is authenticated and decrypted  
3. Plaintext MAVLink is forwarded to Mission Planner  


## Usage

### Encrypt (Pi side)
python proxy.py --mode encrypt \
--listen-ip 0.0.0.0 --listen-port 14550 \
--forward-ip <WINDOWS_IP> --forward-port 14551

### Decrypt (Windows side)
python proxy.py --mode decrypt \
--listen-ip 0.0.0.0 --listen-port 14551 \
--forward-ip 127.0.0.1 --forward-port 14550

## References
- RFC 8439 – ChaCha20 and Poly1305 for IETF Protocols  
- MAVSec: Securing the MAVLink Protocol for ArduPilot/PX4  
- Enhancing MAVLink Security in UAV Systems (2025)  
- Secure MAVLink Messaging with ChaCha20-Poly1305  
- ChaCha20-Poly1305 for Embedded and UAV Systems  
- Survey on Cryptographic Methods for UAV Communication Security  
