#!/bin/bash

# XRayAuth Installation Script
# Author: Akki
# Description: Automated setup for XRayAuth Session Hijack Detection Tool

set -e

echo "=================================================="
echo "🛡️  XRayAuth Installation Script"
echo "📦  Setting up Session Hijack Detection Tool"
echo "👤  Author: Akki"
echo "=================================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "⚠️  This script should not be run as root for security reasons."
   echo "   Please run as a regular user. Sudo will be used when needed."
   exit 1
fi

# Update package lists
echo "[*] Updating package lists..."
sudo apt update

# Install system dependencies
echo "[*] Installing system dependencies..."
sudo apt install -y python3-venv python3-pip python3-scapy python3-dev build-essential libpcap-dev

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment and install Python packages
echo "[*] Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Make CLI script executable
chmod +x cli.py

# Create desktop shortcut (optional)
if command -v desktop-file-install &> /dev/null; then
    echo "[*] Creating desktop shortcut..."
    cat > xrayauth.desktop << EOF
[Desktop Entry]
Name=XRayAuth
Comment=Session Hijack Detection Tool
Exec=gnome-terminal -- bash -c 'cd $(pwd) && source venv/bin/activate && sudo python3 cli.py; read -p "Press Enter to close..."'
Icon=security-high
Terminal=true
Type=Application
Categories=Network;Security;
EOF
    desktop-file-install --dir=$HOME/.local/share/applications xrayauth.desktop
    rm xrayauth.desktop
fi

echo ""
echo "✅ Installation completed successfully!"
echo ""
echo "📋 Usage Instructions:"
echo "   1. Activate virtual environment: source venv/bin/activate"
echo "   2. Run basic HTTP monitoring: sudo python3 cli.py -i eth0"
echo "   3. Run with HTTPS support: sudo python3 cli.py -i eth0 --https"
echo ""
echo "📖 For more information, see README.md"
echo "⚠️  Remember: Only use on networks you own or have permission to test!"
echo ""