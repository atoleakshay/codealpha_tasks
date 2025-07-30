# XRayAuth Project Summary

## 🛡️ Overview
XRayAuth is a comprehensive session hijack detection tool designed for network security professionals and penetration testers. It monitors HTTP and HTTPS traffic to identify suspicious authentication token usage patterns that may indicate session hijacking attacks.

## 📁 Project Structure

```
XRayAuth/
├── cli.py                 # Main application script
├── requirements.txt       # Python dependencies
├── install.sh            # Automated installation script
├── README.md             # Comprehensive documentation
├── config_example.ini    # Configuration file example
├── test_demo.py          # Demonstration script
├── PROJECT_SUMMARY.md    # This file
└── venv/                 # Python virtual environment (created during setup)
```

## 🔧 Core Components

### 1. **cli.py** - Main Application
- **Size**: 6.9KB, 207 lines
- **Purpose**: Core detection engine
- **Features**:
  - Real-time packet capture using Scapy
  - HTTP/HTTPS traffic analysis
  - Session token extraction and tracking
  - Anomaly detection algorithm
  - JSON logging with timestamps
  - mitmproxy integration for HTTPS support
  - Configurable network interface monitoring

### 2. **requirements.txt** - Dependencies
- **Size**: 49B, 3 lines
- **Contents**:
  - `scapy>=2.4.5` - Packet capture and analysis
  - `mitmproxy>=9.0.0` - HTTPS proxy and interception
  - `configparser>=5.3.0` - Configuration file handling

### 3. **install.sh** - Installation Script
- **Size**: 2.2KB, 72 lines
- **Purpose**: Automated setup and dependency installation
- **Features**:
  - System package installation
  - Virtual environment creation
  - Python dependency management
  - Desktop shortcut creation
  - Security checks (prevents root execution)

### 4. **README.md** - Documentation
- **Size**: 4.7KB, 186 lines
- **Contents**:
  - Installation instructions
  - Usage examples
  - Feature descriptions
  - Security considerations
  - Troubleshooting guide
  - Legal and ethical guidelines

### 5. **config_example.ini** - Configuration Template
- **Size**: 562B, 19 lines
- **Purpose**: Shows users how to customize settings
- **Includes**:
  - Network interface selection
  - Log file path configuration
  - Custom token patterns
  - Proxy settings
  - Detection sensitivity options

### 6. **test_demo.py** - Demonstration Script
- **Size**: 3.1KB, 96 lines
- **Purpose**: Educational demonstration
- **Features**:
  - Simulates legitimate user sessions
  - Demonstrates hijack scenarios
  - Shows expected detection output
  - Threading for concurrent simulation

## 🎯 Key Features

### Detection Capabilities
- **Session Cookie Monitoring**: Tracks `session=` cookies
- **Bearer Token Detection**: Monitors `Authorization: Bearer` headers
- **IP Address Correlation**: Detects token reuse from different IPs
- **User Agent Analysis**: Identifies suspicious client changes
- **Real-time Alerting**: Immediate notification of anomalies

### Technical Specifications
- **Protocol Support**: HTTP (port 80) and HTTPS (via proxy)
- **Network Interfaces**: Configurable (eth0, wlan0, etc.)
- **Logging Format**: JSON with ISO timestamps
- **Memory Usage**: In-memory session database
- **Performance**: Minimal overhead packet processing

### Security Features
- **Ethical Use Controls**: Built-in usage warnings
- **Permission Checks**: Requires appropriate network access
- **Configuration Security**: User-specific config files
- **Process Management**: Clean shutdown handling

## 🚀 Usage Scenarios

### 1. **Network Security Testing**
```bash
sudo python3 cli.py -i eth0
```

### 2. **HTTPS Traffic Analysis**
```bash
sudo python3 cli.py -i wlan0 --https
```

### 3. **Custom Logging**
```bash
sudo python3 cli.py -i enp0s3 -l /var/log/security/xrayauth.json
```

## 📊 Detection Algorithm

1. **Traffic Capture**: Monitor specified network interface
2. **Token Extraction**: Parse HTTP headers for authentication tokens
3. **Session Tracking**: Maintain database of token→(IP, User-Agent) mappings
4. **Anomaly Detection**: Flag tokens used from different sources
5. **Alert Generation**: Log and display suspicious activity

## 🛠️ Technical Requirements

### System Requirements
- **OS**: Linux (Kali Linux recommended)
- **Python**: 3.7+
- **Privileges**: Root/sudo for packet capture
- **Memory**: ~50MB base usage
- **Network**: Access to monitored interface

### Dependencies
- **System**: libpcap-dev, python3-dev, build-essential
- **Python**: scapy, mitmproxy, configparser
- **Optional**: desktop-file-utils (for GUI shortcut)

## 🔒 Security Considerations

### Ethical Use
- **Authorized Testing Only**: Use only on owned/permitted networks
- **Legal Compliance**: Respect local laws and regulations
- **Privacy Protection**: Handle captured data responsibly
- **Documentation**: Maintain testing records and permissions

### Limitations
- **HTTP Only**: Basic mode limited to unencrypted traffic
- **Certificate Requirements**: HTTPS needs proper cert setup
- **Memory Persistence**: Session data lost on restart
- **Network Position**: Requires appropriate network access

## 🎓 Educational Value

### Learning Objectives
- **Network Security**: Understanding session hijacking attacks
- **Traffic Analysis**: Packet capture and inspection techniques
- **Python Development**: Security tool development practices
- **Ethical Hacking**: Responsible security testing methods

### Use Cases
- **Cybersecurity Training**: Hands-on attack detection
- **Penetration Testing**: Session security assessment
- **Network Monitoring**: Continuous security surveillance
- **Incident Response**: Post-breach analysis and forensics

## 📈 Future Enhancements

### Potential Improvements
- **Database Persistence**: SQLite/PostgreSQL backend
- **Machine Learning**: Advanced anomaly detection
- **Web Interface**: Real-time dashboard
- **Alert Integration**: Email/Slack notifications
- **Pattern Learning**: Adaptive token recognition
- **Performance Optimization**: Multi-threading support

---

**Author**: Akki  
**Version**: 1.0.0  
**License**: Educational/Authorized Testing Use Only  
**Created**: 2025  

⚠️ **Important**: This tool is designed for educational purposes and authorized security testing only. Users are responsible for ensuring compliance with applicable laws and obtaining proper permissions before use.