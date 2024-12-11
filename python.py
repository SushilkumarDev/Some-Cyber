#!/usr/bin/python

import socket
import time
from datetime import datetime

# Function to scan a single port
def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Timeout for the socket connection
            result = s.connect_ex((target, port))  # Attempt to connect
            if result == 0:
                return True  # Port is open
    except Exception as e:
        pass
    return False  # Port is closed or unreachable

# Function to check for commonly vulnerable ports
def is_vulnerable_port(port):
    vulnerable_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3389: "RDP"
    }
    return vulnerable_ports.get(port, None)

# Main function
def main():
    # Input target and port range
    target = input("Enter the target IP or hostname: ")
    start_port = int(input("Enter the start port: "))
    end_port = int(input("Enter the end port: "))

    # Resolve hostname to IP
    try:
        target_ip = socket.gethostbyname(target)
        print(f"Scanning target: {target} ({target_ip})")
    except socket.gaierror:
        print("Error: Unable to resolve hostname.")
        return

    # Record start time
    start_time = datetime.now()
    print(f"Scan started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Scan ports in the specified range
    open_ports = []
    for port in range(start_port, end_port + 1):
        if scan_port(target_ip, port):
            port_info = is_vulnerable_port(port)
            if port_info:
                print(f"[!] Vulnerable Port Open: {port} ({port_info})")
            else:
                print(f"[+] Port Open: {port}")
            open_ports.append(port)

    # Record end time
    end_time = datetime.now()
    print(f"Scan completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    duration = end_time - start_time
    print(f"Time taken: {duration}")

    # Summary
    print("\nSummary:")
    if open_ports:
        for port in open_ports:
            port_info = is_vulnerable_port(port)
            if port_info:
                print(f"[!] {port} ({port_info}) - Vulnerable")
            else:
                print(f"[+] {port} - Open")
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()
