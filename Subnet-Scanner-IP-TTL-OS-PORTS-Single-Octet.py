##### 256-IPS Port Scanner Python 3.12 ##### By Sergi Morlà.
# This script takes an input IP address in format X.X.X.X and scans all the open ports in the same octet.

import socket
import platform
import subprocess
import re
import concurrent.futures

def getttl(ip, system):                                                                                                 # GETTTL gets the TTL out of the PING response.
    command = ["ping", "-n", "1", ip] if system == "Windows" else ["ping", "-c", "1", ip]                               # Command PING is different depending on the OS that executes it (Windows, Linux, Mac...).
    try:
        output = subprocess.run(command, capture_output=True, text=True, timeout=3).stdout                              # Timeout does not work well with values under 3.
        ttl_match = re.search(r'TTL=(\d+)', output, re.IGNORECASE)
        if ttl_match:
            return ip, int(ttl_match.group(1))
    except subprocess.TimeoutExpired:                                                                                   # print(f"IP: {ip}\t Ping Timeout")     # We could print the PING timeouts.
        return ip, None
    except Exception as e:                                                                                              # print(f"IP: {ip}\t Ping Error {e}")   # We could print the PING errors.
        return ip, None
    return ip, None

def getos(ttl):                                                                                                         # Classifying TTLs depending on the OS.
    if ttl is None:
        return "Not Found          "
    elif ttl <= 64:
        return "Linux, Mac & Others"
    elif ttl <= 128:
        return "Windows            "
    else:
        return "Uncertain          "

def iprange(base_ip):                                                                                                   # Create a list of IPs with common first three octets and with the last octet going from 000 to 254.
    prefix = base_ip.rsplit('.', 1)[0]
    return [f"{prefix}.{str(i)}" for i in range(255)]

def portcheck(ip, port: int) -> int:                                                                                    # This function checks if a single port is open.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        if s.connect_ex((ip, port)) == 0:
            return port
    return None

def scanports(ip):
    openports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=256) as executor:                                            # Execute multiple PORTCHECK function in parallel.
        results = executor.map(lambda p: portcheck(ip, p), range(1, 65536))                                             # Scan the full range of ports.
    openports = [port for port in results if port]
    if openports:
        return (f"{', '.join(map(str, openports))}")                                                                    # Returns a string with the list of open ports.
    else:
        return None

def main():
    system = platform.system()
    print("Introduce your IP address in format X.X.X.X to start the scan of the last octet.")
    base_ip = input("IP: ")
    ips = iprange(base_ip)
    print("Scanning...\n")
    with concurrent.futures.ThreadPoolExecutor(max_workers=256) as executor:                                            # ThreadPoolExecutor throws multiple PINGs simultaneously.
        results = list(executor.map(lambda ip: getttl(ip, system), ips))
    for ip, ttl in results:                                                                                             # Print the IPs that got an answer with their TTL, OS & Open Ports.
        if ttl is not None:
            print(f"IP: {ip} \t TTL: {ttl} \t OS: {getos(ttl)}\t Ports: {scanports(ip)}")

if __name__ == "__main__":
    main()