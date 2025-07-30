# 🛡️ XRayAuth - Session Hijack Detection Tool

A powerful network security tool designed to detect session hijacking attacks by monitoring HTTP and HTTPS traffic for authentication token anomalies.

## Features

- **Real-time Traffic Monitoring**: Captures and analyzes HTTP/HTTPS traffic
- **Session Hijack Detection**: Identifies suspicious token reuse from different IP addresses
- **Dual Protocol Support**: Monitors both HTTP (port 80) and HTTPS (via mitmproxy)
- **Token Pattern Recognition**: Detects various authentication tokens (cookies, Bearer tokens)
- **Comprehensive Logging**: JSON-formatted logs with timestamps
- **User Agent Analysis**: Tracks user agent changes for enhanced detection
- **Configurable Interface**: Persistent configuration via INI file

## Installation

### Prerequisites

- Python 3.7+
- Root/sudo privileges (required for packet capture)
- Kali Linux or similar penetration testing distribution

### Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install scapy mitmproxy
```

## Usage

### Basic HTTP Monitoring

```bash
sudo python3 cli.py -i eth0
```

### HTTPS Monitoring (with mitmproxy)

```bash
sudo python3 cli.py -i eth0 --https
```

### Custom Interface and Log File

```bash
sudo python3 cli.py -i wlan0 -l /path/to/custom/log.json
```

### Command Line Options

- `-i, --interface`: Network interface to monitor (default: eth0)
- `-l, --log`: Log file path (default: ~/xrayauth_logs.json)
- `--https`: Enable HTTPS monitoring via mitmproxy

## How It Works

### Detection Algorithm

1. **Traffic Capture**: Monitors network traffic on specified interface
2. **Token Extraction**: Identifies authentication tokens in HTTP headers:
   - Session cookies (`Cookie: session=...`)
   - Bearer tokens (`Authorization: Bearer ...`)
3. **Anomaly Detection**: Compares current token usage with stored session data
4. **Alert Generation**: Flags suspicious activity when tokens are reused from different IPs

### Session Database

The tool maintains an in-memory database of active sessions:
- **Token**: Authentication token string
- **IP Address**: Source IP of the session
- **User Agent**: Browser/client identifier

### Log Format

Events are logged in JSON format:

```json
{
  "type": "anomaly",
  "timestamp": "2024-01-15T10:30:45.123456",
  "token": "session=abc123...",
  "new_ip": "192.168.1.100",
  "old_ip": "192.168.1.50",
  "old_ua": "Mozilla/5.0...",
  "new_ua": "curl/7.68.0"
}
```

## Configuration

The tool creates a configuration file at `~/.xrayauth_config.ini`:

```ini
[XRayAuth]
interface = eth0
log = /home/user/xrayauth_logs.json
```

## Security Considerations

### Ethical Use Only
This tool is designed for:
- Network security testing
- Authorized penetration testing
- Educational purposes
- Incident response and forensics

### Legal Compliance
- Only use on networks you own or have explicit permission to test
- Comply with local laws and regulations
- Respect privacy and data protection requirements

## Limitations

- **HTTP Only**: Basic mode only captures unencrypted HTTP traffic
- **HTTPS Dependency**: HTTPS monitoring requires mitmproxy and proper certificate setup
- **Memory Storage**: Session database is not persistent across restarts
- **Network Position**: Requires network access to monitor target traffic

## Troubleshooting

### Permission Errors
```bash
# Run with sudo for packet capture privileges
sudo python3 cli.py
```

### Interface Not Found
```bash
# List available interfaces
ip link show
# or
ifconfig -a
```

### HTTPS Certificate Issues
For HTTPS monitoring, clients need to trust mitmproxy's certificate:
```bash
# Export mitmproxy certificate
mitmdump --set confdir=~/.mitmproxy
# Install certificate on target devices
```

## Example Output

```
==================================================
🛡️  XRayAuth - Session Hijack Detection Tool
📦  Version: 1.0.0
👤  Author: Akki
==================================================
[*] Monitoring interface eth0 for HTTP traffic...
[2024-01-15 10:30:45.123456] GET http://example.com/login

[!] Possible Session Hijack Detected!
[-] Token reused from new IP: 192.168.1.100
[-] Old IP: 192.168.1.50, Old UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for compliance with applicable laws and regulations.

## Author

**Akki** - Security Researcher and Tool Developer

---

⚠️ **Disclaimer**: This tool is for authorized security testing only. Unauthorized network monitoring may violate laws and regulations. Use responsibly and ethically.