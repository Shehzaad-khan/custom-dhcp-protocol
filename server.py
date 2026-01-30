import socket
import threading
import signal
import sys
import time
import ssl

server_ip = "192.168.0.102"
server_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
interface = "enp0s3"
lease_time = 30

ip_pools = {
    "192.168.0.0/24": ["192.168.0.150", "192.168.0.151"],
    "192.168.1.0/24": ["192.168.1.150", "192.168.1.151"],
    "10.0.0.0/24": ["10.0.0.1", "10.0.0.2"]
}

leased_ips = {}
ip_mac_map = {}
mac_ip_history = {}

raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
raw_sock.bind((interface, 0))

def cleanup(sig, frame):
    raw_sock.close()
    print("\n[!] DHCP Server terminated.")
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)

def match_subnet(ip_part):
    for subnet, ips in ip_pools.items():
        base = subnet.rsplit('.', 1)[0]
        if ip_part.startswith(base):
            return ips
    return []

def is_same_subnet(ip1, ip2):
    return ip1.rsplit(".", 1)[0] == ip2.rsplit(".", 1)[0]

def assign_ip(mac, ip_prefix):
    now = time.time()

    if mac in leased_ips:
        prev_ip, lease_end = leased_ips[mac]
        if lease_end > now and is_same_subnet(prev_ip, ip_prefix):
            return prev_ip

    if mac in mac_ip_history:
        prev_ip = mac_ip_history[mac]
        if is_same_subnet(prev_ip, ip_prefix) and prev_ip not in ip_mac_map:
            leased_ips[mac] = (prev_ip, now + lease_time)
            ip_mac_map[prev_ip] = mac
            return prev_ip

    for ip in match_subnet(ip_prefix):
        if ip not in ip_mac_map:
            leased_ips[mac] = (ip, now + lease_time)
            ip_mac_map[ip] = mac
            mac_ip_history[mac] = ip
            return ip
    return None

def release_expired_ips():
    while True:
        time.sleep(10)
        now = time.time()
        expired = [mac for mac, (_, end) in leased_ips.items() if end < now]
        for mac in expired:
            ip, _ = leased_ips.pop(mac)
            ip_mac_map.pop(ip, None)
            print(f"[!] Lease expired for {ip}")

def build_packet(mac_dst, ip, msg_type):
    eth_hdr = mac_dst + server_mac + b"\x08\x00"
    ip_hdr = b'\x45' + b'\x00' * 19
    payload = (
        msg_type.encode() + b"|" +
        socket.inet_aton(ip) + b"|" +
        socket.inet_aton(server_ip)
    )
    return eth_hdr + ip_hdr + payload

def parse_dhcp_packet(packet):
    if len(packet) < 54:
        return None, None, None
    if packet[12:14] != b'\x08\x00':
        return None, None, None

    src_mac = packet[6:12]
    payload = packet[34:]

    if b"DHCP" not in payload:
        return None, None, None

    parts = payload.split(b"|")
    if len(parts) >= 2:
        return src_mac, parts[0].decode().strip(), parts[1].decode().strip()
    return None, None, None

def dhcp_handler():
    while True:
        packet, _ = raw_sock.recvfrom(2048)
        mac, msg_type, requested_ip = parse_dhcp_packet(packet)
        if not msg_type:
            continue

        if msg_type == "DHCP DISCOVER":
            assigned_ip = assign_ip(mac, requested_ip)
            if assigned_ip:
                raw_sock.send(build_packet(mac, assigned_ip, "DHCP OFFER"))
                print(f"[+] OFFERED {assigned_ip} to {mac.hex(':')}")

        elif msg_type == "DHCP REQUEST":
            if ip_mac_map.get(requested_ip) == mac:
                raw_sock.send(build_packet(mac, requested_ip, "DHCP ACKNOWLEDGE"))
                print(f"[+] ACK {requested_ip} for {mac.hex(':')}")
            else:
                raw_sock.send(build_packet(mac, requested_ip, "DHCP NOT AVAILABLE"))
                print(f"[-] {requested_ip} not available")

def ssl_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("cert.pem", "key.pem")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", 4443))
    sock.listen(5)

    with context.wrap_socket(sock, server_side=True) as ssock:
        print("[*] SSL control channel running on port 4443")
        while True:
            conn, addr = ssock.accept()
            msg = conn.recv(1024).decode()
            print(f"[SSL] {addr} → {msg}")
            conn.send(b"ACKNOWLEDGED")
            conn.close()

print("[*] DHCP Server started.")
threading.Thread(target=dhcp_handler, daemon=True).start()
threading.Thread(target=release_expired_ips, daemon=True).start()
threading.Thread(target=ssl_server, daemon=True).start()
signal.pause()
