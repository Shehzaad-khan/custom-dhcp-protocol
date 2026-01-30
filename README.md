# Custom DHCP Protocol

A lightweight, custom implementation of the Dynamic Host Configuration Protocol (DHCP) for automatic IP address assignment in local networks. This implementation uses raw sockets for Layer 2 communication and includes SSL/TLS for secure control channel communication.

## 🚀 Features

- **Custom DHCP Protocol Implementation**: Full DHCP workflow with DISCOVER, OFFER, REQUEST, and ACKNOWLEDGE messages
- **Multiple Subnet Support**: Configurable IP pools for different subnets (192.168.0.x, 192.168.1.x, 10.0.0.x)
- **Lease Management**: Automatic IP lease expiration and renewal (default 30 seconds)
- **IP History Tracking**: Clients can reclaim previously assigned IPs if available
- **SSL/TLS Control Channel**: Secure confirmation channel on port 4443
- **Raw Socket Communication**: Direct Layer 2 Ethernet frame manipulation
- **Interactive Client**: User-friendly IP prefix selection

## 📋 Prerequisites

- **Operating System**: Linux (tested on systems with network interfaces)
- **Python Version**: Python 3.6+
- **Root Privileges**: Required for raw socket operations
- **SSL Certificates**: For secure communication (cert.pem and key.pem)

### Required Python Libraries

```bash
# Standard library modules (no additional installation needed)
- socket
- struct
- ssl
- signal
- sys
- time
- fcntl
- threading
```

## 🔧 Installation

1. **Clone the repository**:
```bash
git clone https://github.com/Shehzaad-khan/custom-dhcp-protocol.git
cd custom-dhcp-protocol
```

2. **Generate SSL certificates** (for the server):
```bash
openssl req -new -x509 -keyout key.pem -out cert.pem -days 365 -nodes
```

3. **Configure network interface**:
   - Edit `server.py` and `client.py` to set your network interface name
   ```python
   interface = "enp0s3"  # Change to your interface (e.g., eth0, wlan0)
   ```

4. **Configure server IP and MAC** (in `server.py`):
   ```python
   server_ip = "192.168.0.102"  # Set your server IP
   server_mac = b"\xaa\xbb\xcc\xdd\xee\xff"  # Optional: customize MAC
   ```

## 🎯 Usage

### Running the DHCP Server

```bash
sudo python3 server.py
```

The server will:
- Start listening for DHCP requests on the specified interface
- Launch three background threads:
  - DHCP packet handler
  - Lease expiration manager
  - SSL control channel (port 4443)

### Running the DHCP Client

```bash
sudo python3 client.py
```

The client will:
1. Prompt you to enter an IP prefix (e.g., `192.168.1`)
2. Send a DHCP DISCOVER message
3. Receive a DHCP OFFER from the server
4. Send a DHCP REQUEST for the offered IP
5. Receive a DHCP ACKNOWLEDGE
6. Establish an SSL connection for confirmation

### Example Session

**Client Output**:
```
Enter desired IP prefix (e.g., 192.168.1): 192.168.0
[*] Sent DHCP DISCOVER for subnet: 192.168.0
[+] OFFERED IP: 192.168.0.150 from Server: 192.168.0.102
[*] Sent DHCP REQUEST for IP: 192.168.0.150
[+] IP 192.168.0.150 assigned successfully.
[SSL] Server response: ACKNOWLEDGED
```

**Server Output**:
```
[*] DHCP Server started.
[*] SSL control channel running on port 4443
[+] OFFERED 192.168.0.150 to aa:bb:cc:dd:ee:ff
[+] ACK 192.168.0.150 for aa:bb:cc:dd:ee:ff
[SSL] ('192.168.0.101', 45678) → REQUEST IP CONFIRMATION
```

## 🏗️ Architecture

### DHCP Flow

```
Client                          Server
   |                               |
   |--- DHCP DISCOVER ------------>|
   |    (with IP prefix)           |
   |                               |
   |<-- DHCP OFFER ----------------|
   |    (IP + Server IP)           |
   |                               |
   |--- DHCP REQUEST ------------->|
   |    (requested IP)             |
   |                               |
   |<-- DHCP ACKNOWLEDGE ----------|
   |    or NOT AVAILABLE           |
   |                               |
   |=== SSL Confirmation =========>|
   |<== ACKNOWLEDGED ==============|
```

### IP Pool Configuration

The server maintains configurable IP pools for different subnets:

```python
ip_pools = {
    "192.168.0.0/24": ["192.168.0.150", "192.168.0.151"],
    "192.168.1.0/24": ["192.168.1.150", "192.168.1.151"],
    "10.0.0.0/24": ["10.0.0.1", "10.0.0.2"]
}
```

### Lease Management

- **Lease Duration**: 30 seconds (configurable via `lease_time` variable)
- **Automatic Expiration**: Background thread releases expired leases every 10 seconds
- **IP History**: Clients can reclaim their previous IP if it's available

## 🔐 Security Considerations

- **Raw Sockets**: Requires root/admin privileges; use in controlled environments only
- **SSL/TLS**: Uses self-signed certificates by default (suitable for testing)
- **No Authentication**: Current implementation doesn't authenticate clients
- **Network Interface Binding**: Limited to a single network interface

## ⚙️ Configuration Options

### Server Configuration (`server.py`)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `server_ip` | `192.168.0.102` | Server's IP address |
| `interface` | `enp0s3` | Network interface name |
| `lease_time` | `30` | IP lease duration in seconds |
| `ip_pools` | Multiple subnets | Available IP addresses per subnet |

### Client Configuration (`client.py`)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `interface` | `enp0s3` | Network interface name |

## 🐛 Troubleshooting

### Common Issues

1. **Permission Denied**
   ```
   Solution: Run with sudo/root privileges
   ```

2. **Interface Not Found**
   ```
   Solution: Check interface name with 'ip link' or 'ifconfig'
   ```

3. **SSL Certificate Error**
   ```
   Solution: Generate certificates using the openssl command above
   ```

4. **No DHCP Response**
   ```
   Solution: Ensure client and server are on the same network interface
   ```

## 📝 Technical Details

- **Protocol**: Custom DHCP-like protocol over raw Ethernet frames
- **Message Format**: `MESSAGE_TYPE|DATA|...` (pipe-separated)
- **Ethernet Type**: `0x0800` (IPv4)
- **SSL Port**: `4443`
- **Packet Structure**: Ethernet Header (14 bytes) + IP Header (20 bytes) + Payload

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## 📄 License

This project is open source and available for educational purposes.

## ⚠️ Disclaimer

This is a custom implementation for educational purposes and testing in controlled environments. It is **not** intended for production use or to replace standard DHCP servers. Use at your own risk.

## 👤 Author

**Shehzaad Khan**
- GitHub: [@Shehzaad-khan](https://github.com/Shehzaad-khan)

## 🙏 Acknowledgments

- Inspired by the standard DHCP protocol (RFC 2131)
- Built for learning low-level networking concepts