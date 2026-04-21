import argparse
import os
import socket
import sys
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

DEBUG = True

# must be exactly 32 bytes
KEY = b"0123456789ABCDEF0123456789ABCDEF"

# packet format:
# [12-byte nonce][ciphertext + auth tag]
NONCE_LEN = 12
BUF_SIZE = 4096
TAG_LEN = 16


def debug(msg: str):
    if DEBUG:
        print(msg)

# PI Proxy Mode receives plaintext MAVLink UDP packets
# encrypts them and then frowards the encrypted packets
def encrypt_mode(listen_ip, listen_port, forward_ip, forward_port):
    aead = ChaCha20Poly1305(KEY)

    sock_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock_in.bind((listen_ip, listen_port))

    print(f"[encrypt] Listening on {listen_ip}:{listen_port} for plaintext packets")
    print(f"[encrypt] Forwarding encrypted packets to {forward_ip}:{forward_port}")
    print("[encrypt] Press Ctrl+C to stop")

    try:
        while True:
            data, addr = sock_in.recvfrom(BUF_SIZE)

            nonce = os.urandom(NONCE_LEN)
            ciphertext = aead.encrypt(nonce, data, None)
            packet = nonce + ciphertext

            sock_out.sendto(packet, (forward_ip, forward_port))

            debug(
                f"[encrypt] {addr[0]}:{addr[1]} -> {forward_ip}:{forward_port} | "
                f"plain={len(data)} bytes, encrypted={len(packet)} bytes"
            )

            if DEBUG:
                print(f"[encrypt] plaintext: {data.hex()}")
                print(f"[encrypt] packet:    {packet.hex()}")

    except KeyboardInterrupt:
        print("\n[encrypt] stopped by user")

    finally:
        sock_in.close()
        sock_out.close()


# Host side (windows) receives encrypted UDP packets 
# decrypts them and then forwards to Mission Planner
def decrypt_mode(listen_ip, listen_port, forward_ip, forward_port):
    
    aead = ChaCha20Poly1305(KEY)

    sock_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock_in.bind((listen_ip, listen_port))

    print(f"[decrypt] Listening on {listen_ip}:{listen_port} for encrypted packets")
    print(f"[decrypt] Forwarding plaintext packets to {forward_ip}:{forward_port}")
    print("[decrypt] Press Ctrl+C to stop")

    try:
        while True:
            packet, addr = sock_in.recvfrom(BUF_SIZE)

            if len(packet) < NONCE_LEN + TAG_LEN:
                debug(f"[decrypt] packet too short from {addr[0]}:{addr[1]}")
                continue

            nonce = packet[:NONCE_LEN]
            ciphertext = packet[NONCE_LEN:]

            try:
                plaintext = aead.decrypt(nonce, ciphertext, None)
            except Exception as e:
                debug(f"[decrypt] failed auth/decrypt from {addr[0]}:{addr[1]}: {e}")
                continue

            sock_out.sendto(plaintext, (forward_ip, forward_port))

            debug(
                f"[decrypt] {addr[0]}:{addr[1]} -> {forward_ip}:{forward_port} | "
                f"encrypted={len(packet)} bytes, plain={len(plaintext)} bytes"
            )

            if DEBUG:
                print(f"[decrypt] packet:    {packet.hex()}")
                print(f"[decrypt] plaintext: {plaintext.hex()}")

    except KeyboardInterrupt:
        print("\n[decrypt] stopped by user")

    finally:
        sock_in.close()
        sock_out.close()


def main():
    parser = argparse.ArgumentParser(description="UDP encryption/decryption proxy for MAVLink demo")
    parser.add_argument("--mode", choices=["encrypt", "decrypt"], required=True)
    parser.add_argument("--listen-ip", required=True)
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--forward-ip", required=True)
    parser.add_argument("--forward-port", type=int, required=True)

    args = parser.parse_args()

    if len(KEY) != 32:
        print("Error: KEY must be exactly 32 bytes long")
        return 1

    if args.mode == "encrypt":
        encrypt_mode(args.listen_ip, args.listen_port, args.forward_ip, args.forward_port)
    else:
        decrypt_mode(args.listen_ip, args.listen_port, args.forward_ip, args.forward_port)

    return 0


if __name__ == "__main__":
    sys.exit(main())
