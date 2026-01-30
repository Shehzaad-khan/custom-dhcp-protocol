# --- DHCP Client ---
import socket
import struct
import ssl
import signal
import sys
import time
import fcntl

interface = "enp0s3"

def get_mac(interface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(
        s.fileno(),
        0x8927,
        struct.pack('256s', interface.encode('utf-8')[:15])
    )
    return info[18:24]

client_mac = get_mac(interface)

raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
raw_sock.bind((interface, 0))

def cleanup(sig, frame):
    raw_sock.close()
    print("\n[!] DHCP Client terminated.")
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)

def get_ip_from_user():
    while True:
        ip_prefix = input("Enter desired IP prefix (e.g., 192.168.1): ").strip()
        parts = ip_prefix.split(".")
        if len(parts) >= 2 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return ip_prefix
        print("[!] Invalid subnet prefix. Try again.")

def send_discover(ip_prefix):
    eth_hdr = b"\xff\xff\xff\xff\xff\xff" + client_mac + b"\x08\x00"
    dummy_ip_hdr = b'\x45' + b'\x00' * 19
    payload = b"DHCP DISCOVER|" + ip_prefix.encode()
    raw_sock.send(eth_hdr + dummy_ip_hdr + payload)
    print("[*] Sent DHCP DISCOVER for subnet:", ip_prefix)

def listen_offer():
    while True:
        packet, _ = raw_sock.recvfrom(2048)
        if b"DHCP OFFER" not in packet:
            continue
        try:
            payload_start = packet.find(b"DHCP OFFER")
            payload = packet[payload_start:]
            parts = payload.split(b"|")
            offered_ip = socket.inet_ntoa(parts[1][:4])
            server_ip = socket.inet_ntoa(parts[2][:4])
            print(f"[+] OFFERED IP: {offered_ip} from Server: {server_ip}")
            return offered_ip, server_ip
        except Exception as e:
            print("[!] OFFER parse error:", e)

def send_request(ip):
    eth_hdr = b"\xff\xff\xff\xff\xff\xff" + client_mac + b"\x08\x00"
    dummy_ip_hdr = b'\x45' + b'\x00' * 19
    payload = b"DHCP REQUEST|" + ip.encode()
    raw_sock.send(eth_hdr + dummy_ip_hdr + payload)
    print("[*] Sent DHCP REQUEST for IP:", ip)

def listen_ack(ip):
    while True:
        packet, _ = raw_sock.recvfrom(2048)
        if b"DHCP ACKNOWLEDGE" in packet:
            print(f"[+] IP {ip} assigned successfully.")
            return True
        elif b"DHCP NOT AVAILABLE" in packet:
            print(f"[-] IP {ip} is already in use.")
            return False

def ssl_confirm(server_ip):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((server_ip, 4443)) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as ssock:
                ssock.sendall(b"REQUEST IP CONFIRMATION")
                msg = ssock.recv(1024)
                print(f"[SSL] Server response: {msg.decode()}")
    except Exception as e:
        print("[SSL] Connection failed:", e)

# --- DHCP Client Flow ---
ip_prefix = get_ip_from_user()
send_discover(ip_prefix)
offered_ip, server_ip = listen_offer()
time.sleep(1)
send_request(offered_ip)

if listen_ack(offered_ip):
    ssl_confirm(server_ip)
