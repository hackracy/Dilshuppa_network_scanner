Dilshuppa Network Scanner:

Dilshuppa Network Scanner is a powerful Python-based tool for scanning devices in a local network, detecting open ports, identifying services running on those ports, checking for vulnerabilities in those services, and providing detailed information about each device, such as IP, MAC address, hostname, and operating system.

This tool is designed to be easy to use and is a great way to learn about network scanning, security vulnerabilities, and OS detection.

Features

IP Address Detection: Automatically detects your local IP address.
Subnet Scan: Performs an ARP scan to discover all devices connected to the network.
Device Information: Provides information about the device, including its IP, MAC address, hostname, and operating system.
Advanced Port Scanning: Scans a range of ports to detect open services.
Vulnerability Scanning: Checks for known vulnerabilities in services running on discovered devices by matching their versions with a vulnerability database (CVE).
OS Detection: Uses nmap to identify the operating system of devices in the network.
Prerequisites

Before you can run the tool, you'll need to install the required dependencies. The tool is built using Python 3, so make sure Python 3.x is installed.

Dependencies
nmap: For scanning open ports and detecting services.
scapy: For performing ARP network discovery.
psutil: For system and process monitoring.
requests: For making HTTP requests (if needed).
You can install the required dependencies by running the following command:
```
pip install -r requirements.txt
```
Installation

Clone the Repository:
Clone the Dilshuppa_network_scanner repository to your local machine:
```
git clone https://github.com/yourusername/Dilshuppa_network_scanner.git
cd Dilshuppa_network_scanner
```
Install the Package:
Install the tool using pip:
```
pip install .
```
This will install the necessary dependencies and make the tool accessible for use in your terminal.
Usage

Once installed, you can easily run the tool with the following command:
```
dilshuppa_network_scanner

```
What Happens When You Run the Tool:
IP Address Detection: The tool will automatically detect your local IP address.
Subnet Scan: It performs an ARP scan across your local network to discover devices connected to the same subnet.
Device Information: For each device detected, the tool will display:
IP Address
MAC Address
Hostname (if resolvable)
Operating System (if detectable using nmap)
Open Ports
Vulnerability Scan: For each open port, the tool checks if there are any known vulnerabilities based on the service's version. If any vulnerabilities are found, their corresponding CVE ID will be displayed.
```
Sample Output:
Tool Name: Dilshuppa Network Scanner
Author: Dilshuppa
Version: 1.1

Features:
- IP Address Detection
- Subnet Scan
- MAC Address, Hostname, OS, Open Ports, and Services Info
- Vulnerability Scanning for Outdated Services
- Advanced Scanning Options
- More Accurate OS Detection

Local IP Address: 192.168.1.10

Performing subnet scan...

Devices found in your network:

IP: 192.168.1.2
MAC: 00:14:22:01:23:45
Hostname: device1.local
Operating System: Linux

Open Ports: {22: {'name': 'ssh', 'port': 22, 'version': 'OpenSSH 7.4'}}
Scanning for vulnerabilities on 192.168.1.2...

No vulnerabilities found for ssh version OpenSSH 7.4 on 192.168.1.2:22

...
```
Configuration
The default port range for scanning is 1-1024. If you want to scan a different range of ports, you can modify the scan_ports function to accept a different range.

You can customize the vulnerability database by editing the check_vulnerabilities function and adding more CVE entries related to different services.

Contribution

Feel free to fork the repository, open issues, and create pull requests. Contributions are always welcome!

How to Contribute:
Fork the repository.
Clone your fork to your local machine.
Create a new branch for your changes.
Make the necessary changes and add tests if applicable.
Submit a pull request describing your changes.
License

This project is open-source and available under the MIT License.

Acknowledgements

nmap: Used for port scanning and OS detection.
scapy: Used for performing ARP scans to discover devices.
psutil: Provides system and process information (if needed).
requests: Used for making HTTP requests for any additional features in the future.
Notes
Permissions: Make sure you have permission to scan the network you're using this tool on. Unauthorized scanning could violate terms of service or local laws.
Accuracy: The OS detection is based on nmap's service and version detection. It may not always be 100% accurate.
