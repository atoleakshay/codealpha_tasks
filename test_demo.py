#!/usr/bin/env python3
"""
XRayAuth Demo Script
Demonstrates session hijack detection capabilities
Author: Akki
"""

import requests
import time
import threading
from datetime import datetime

def simulate_legitimate_session():
    """Simulate a legitimate user session"""
    print(f"[{datetime.now()}] 🟢 Simulating legitimate user session...")
    
    # Simulate session cookie
    session_cookie = "session=abc123def456ghi789"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Cookie': session_cookie
    }
    
    try:
        # Make some legitimate requests
        for i in range(3):
            print(f"[{datetime.now()}] 📤 Legitimate request {i+1}")
            # In a real scenario, this would be captured by XRayAuth
            time.sleep(2)
    except Exception as e:
        print(f"Request failed: {e}")

def simulate_hijack_attempt():
    """Simulate a session hijacking attempt"""
    print(f"[{datetime.now()}] 🔴 Simulating session hijack attempt...")
    
    # Same session cookie, different user agent (attacker)
    session_cookie = "session=abc123def456ghi789"  # Same as legitimate user
    headers = {
        'User-Agent': 'curl/7.68.0',  # Different user agent
        'Cookie': session_cookie
    }
    
    try:
        print(f"[{datetime.now()}] ⚠️  Hijacker using stolen session token")
        print(f"[{datetime.now()}] 🚨 This should trigger XRayAuth detection!")
        # In a real scenario, this would be captured and flagged by XRayAuth
        time.sleep(1)
    except Exception as e:
        print(f"Request failed: {e}")

def main():
    print("=" * 60)
    print("🛡️  XRayAuth Session Hijack Detection Demo")
    print("📦  This demonstrates how XRayAuth detects suspicious activity")
    print("👤  Author: Akki")
    print("=" * 60)
    print()
    
    print("📋 Demo Scenario:")
    print("   1. Legitimate user establishes session")
    print("   2. Attacker steals session token")
    print("   3. Attacker uses token from different IP/User-Agent")
    print("   4. XRayAuth detects anomaly and alerts")
    print()
    
    # Start legitimate session
    legitimate_thread = threading.Thread(target=simulate_legitimate_session)
    legitimate_thread.start()
    
    # Wait a bit, then simulate hijack
    time.sleep(5)
    hijack_thread = threading.Thread(target=simulate_hijack_attempt)
    hijack_thread.start()
    
    # Wait for threads to complete
    legitimate_thread.join()
    hijack_thread.join()
    
    print()
    print("🔍 What XRayAuth Would Detect:")
    print("   • Same session token used from different source")
    print("   • Different User-Agent string")
    print("   • Potential IP address change")
    print("   • Timing anomalies")
    print()
    print("📊 Expected XRayAuth Output:")
    print("   [!] Possible Session Hijack Detected!")
    print("   [-] Token reused from new IP: 192.168.1.100")
    print("   [-] Old IP: 192.168.1.50, Old UA: Mozilla/5.0...")
    print()
    print("✅ Demo completed!")
    print("🚀 Run XRayAuth with: sudo python3 cli.py -i eth0")

if __name__ == "__main__":
    main()