import subprocess
import re

def display_intro():
    intro_message = '''
    ##################################################
    #                   D_NetScanner                 #
    #               Author: DILSHUPPA                #
    #    linkedIn : linkedin.com/in/dilshuppa        #
    ##################################################
    '''
    print(intro_message)
    print("Don't Misuse your Hacking skills. Hacking is an Art So Hackers, So Hackers are Artists, try to respect Them! \n")


def get_ip():
    result = subprocess.run(["ip", "a"], capture_output=True, text=True)
    ip_list = re.findall(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', result.stdout)
    for ip in ip_list:
        if not ip[0].startswith("127."):
            return f"{ip[0]}/{ip[1]}"
    return None
    
def scan_hosts(network):
    print("Starting scan on:", network)
    result = subprocess.run(["nmap", "-sn", network], capture_output=True, text=True)
    hosts = re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", result.stdout)
    return hosts
    
def full_scan(host):
    print("Scanning", host)
    result = subprocess.run(["sudo", "nmap", "-Pn", "-A", "-sS", "-sU", "-p-", "-T4", "-v", host], capture_output=True, text=True)
    print(result.stdout)
    return result.stdout

def find_open_ports(scan_result):
    open_ports = []
    for line in scan_result.splitlines():
        if re.search(r'\d+/(tcp|udp)\s+open', line):
            open_ports.append(line)
    return open_ports

def search_vuln(service):
    service_name = ' '.join(service.split()[2:]) if len(service.split()) >= 3 else service
    if service_name:
        print("Searching for vulnerabilities:", service_name)
        subprocess.run(["searchsploit", service_name])
    else:
        print("Invalid service info")

def run_vuln_scripts(host):
    print("\n[*] Running Nmap vulnerability scripts...\n")
    subprocess.run(["sudo", "nmap", "--script=vuln", "-sV", "-p-", host])

def check_smb(host):
    print("\n[*] Running SMB vulnerability scans...\n")
    subprocess.run(["smbclient", "-L", host, "-N"])
    subprocess.run(["smbmap", "-H", host, "-u", "guest", "-p", ""])
    subprocess.run(["enum4linux", "-a", host])

def capture_traffic():
    print("\n[*] Running tcpdump...\n")
    subprocess.run(["sudo", "tcpdump", "-i", "eth0", "-nn", "-s0", "-v"])

def check_os_vulns(host):
    print("\n[*] Scanning for OS vulnerabilities...\n")
    if "windows" in host.lower():
        print("[*] Scanning Windows SMB vulnerabilities...\n")
        subprocess.run(["sudo", "nmap", "--script", "smb-vuln-ms17-010", "-sV", host])
    elif "linux" in host.lower():
        print("[*] Scanning Linux vulnerabilities...\n")
        subprocess.run(["sudo", "nmap", "--script", "linux", "-sV", host])

def main():
    display_intro() 
    print("Be patient if you have passion ")
    ip = get_ip()
    if not ip:
        print("No IP found")
        return

    hosts = scan_hosts(ip)
    if not hosts:
        print("No hosts found")
        return

    for i, host in enumerate(hosts):
        print(f"{i + 1}: {host}")

    try:
        choice = int(input("Pick a host: "))
    except ValueError:
        print("Invalid input")
        return

    if choice < 1 or choice > len(hosts):
        print("Invalid choice")
        return

    selected_host = hosts[choice - 1]
    scan_result = full_scan(selected_host)
    open_ports = find_open_ports(scan_result)

    for port in open_ports:
        search_vuln(port)

    run_vuln_scripts(selected_host)
    check_smb(selected_host)
    capture_traffic()
    check_os_vulns(selected_host)

if __name__ == "__main__":
    main()
