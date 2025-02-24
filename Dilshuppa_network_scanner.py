#!/usr/bin/env python3
import socket
import os
import subprocess
import platform
import nmap
import psutil
from scapy.all import ARP, Ether, srp
from sys import exit
import requests
import re
import json

# Version info and author info
TOOL_NAME = "Dilshuppa Network Scanner"
AUTHOR = "Dilshuppa"
VERSION = "1.1"

# Print Tool Info
def print_tool_info():
    print(f"Tool Name: {TOOL_NAME}")
    print(f"Author: {AUTHOR}")
    print(f"Version: {VERSION}")
    print("\nFeatures:")
    print("- IP Address Detection")
    print("- Subnet Scan")
    print("- MAC Address, Hostname, OS, Open Ports, and Services Info")
    print("- Vulnerability Scanning for Outdated Services")
    print("- Advanced Scanning Options")
    print("- More Accurate OS Detection\n")

# Get local IP address
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

# Perform ARP scan to detect devices in the subnet
def arp_scan(target_ip):
    print("Performing subnet scan...")
    target_ip = f"{target_ip}/24"
    # Craft ARP request to get all devices in the network
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    devices = []
    for element in answered_list:
        device = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc,
            "hostname": get_device_hostname(element[1].psrc),
            "os": get_device_os(element[1].psrc)
        }
        devices.append(device)
    return devices

# Get the hostname of a device
def get_device_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "Unknown"
    return hostname

# Get the OS details using nmap or other methods
def get_device_os(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, '80')  # Scan a common port to attempt OS detection
        if 'osmatch' in nm[ip]:
            return nm[ip]['osmatch'][0]['name']
        else:
            return "Unknown"
    except Exception:
        return "Unknown"

# Advanced Port Scanning with Nmap
def scan_ports(ip, port_range="1-1024"):
    nm = nmap.PortScanner()
    print(f"Scanning open ports for IP: {ip} within range: {port_range}")
    try:
        nm.scan(ip, port_range)
        return nm[ip]['tcp']
    except KeyError:
        return {}

# Check for known vulnerable service versions (Simple example using CVE database)
def check_vulnerabilities(service_name, version):
    vulnerabilities = {
        "apache": {
            "2.4.0": "CVE-2021-22995",
            "2.4.1": "CVE-2021-22996",
        },
        "nginx": {
            "1.14.0": "CVE-2021-23047",
        },
        "ftp": {
            "3.1.2": "CVE-2021-22991",
        }
    }
    
    if service_name in vulnerabilities and version in vulnerabilities[service_name]:
        return vulnerabilities[service_name][version]
    return None

# Scan for vulnerabilities
def perform_vuln_scan(devices):
    for device in devices:
        ip = device['ip']
        open_ports = scan_ports(ip)
        for port, details in open_ports.items():
            service_name = details['name']
            version = details.get('version', 'Unknown')
            vuln = check_vulnerabilities(service_name, version)
            if vuln:
                print(f"Vulnerability detected for {service_name} version {version} on {ip}:{port} - CVE: {vuln}")
            else:
                print(f"No vulnerabilities found for {service_name} version {version} on {ip}:{port}")

def print_device_info(devices):
    print("\nDevices found in your network:")
    for device in devices:
        print(f"\nIP: {device['ip']}")
        print(f"MAC: {device['mac']}")
        print(f"Hostname: {device['hostname']}")
        print(f"Operating System: {device['os']}")
        
        open_ports = scan_ports(device['ip'])
        print(f"Open Ports: {open_ports}")
        
        # Perform vulnerability scan for each device
        print(f"Scanning for vulnerabilities on {device['ip']}...\n")
        perform_vuln_scan([device])

def main():
    # Print tool info
    print_tool_info()

    # Get local IP address
    local_ip = get_local_ip()
    print(f"Local IP Address: {local_ip}")

    # Perform ARP Scan to detect devices in the subnet
    devices = arp_scan(local_ip)
    if not devices:
        print("No devices found in the network.")
        exit(1)

    # Print details for each device found
    print_device_info(devices)

if __name__ == "__main__":
    main()
