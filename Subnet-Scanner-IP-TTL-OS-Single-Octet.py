##### Last Octet Subnet Scanner Python 3.12 ##### By Sergi Morlà.
# This script takes a 12-digit input IP address in format "XXX.XXX.XXX.XXX" and scans all the IPs in the last octet.
# It returns as an output the TTL taken from the ICMP response and estimated OS for all the IPs in the same X/24 subnet.

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
        return "Not Found"
    elif ttl <= 64:
        return "Linux, Mac & Others"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Uncertain"

def iprange(base_ip):                                                                                                   # We create a list of IPs with common first three octets and with the last octet going from 000 to 254.
    prefix = base_ip.rsplit('.', 1)[0]
    return [f"{prefix}.{str(i).zfill(3)}" for i in range(255)]                                                          # The extension ".zfill(3)" makes a 3 char string for a tidier presentation ("7" -> "007").

def main():
    system = platform.system()
    print("Introduce your 12-digit IP address in format XXX.XXX.XXX.XXX to start the scan of the last octet.")          # Requires a proper user input of 12 digits.
    base_ip = input("IP: ")                                                                                             # Typically a default house subnet would have the format 192.168.000.000/16.
    ips = iprange(base_ip)
    print("Scanning...\n")
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:                                             # ThreadPoolExecutor throws multiple PINGs simultaneously.
        results = list(executor.map(lambda ip: getttl(ip, system), ips))
    for ip, ttl in results:                                                                                             # We print the IPs that got an answer with their TTL and OS.
        if ttl is not None:
            print(f"IP: {ip} \t TTL: {ttl} \t OS: {getos(ttl)}")

if __name__ == "__main__":
    main()
