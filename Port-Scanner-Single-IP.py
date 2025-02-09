##### 1-IP Port Scanner Python 3.12 ##### By Sergi Morlà.
# This script takes an input IP address in format X.X.X.X and scans all the open ports.

import socket
import concurrent.futures

def portcheck(ip, port: int) -> int:                                                                                    # Checks if a single port is open.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        if s.connect_ex((ip, port)) == 0:
            return port
    return None

def scanports(ip):
    openports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=256) as executor:                                            # Execute multiple PORTCHECK function in parallel.
        results = executor.map(lambda p: portcheck(ip, p), range(1, 65536))
    openports = [port for port in results if port]
    if openports:
        print(f"Ports: {', '.join(map(str, openports))}")
    else:
        print(f"No ports found.")

def main():
    print("Introduce your IP address in format X.X.X.X to start the scan of the open ports.")
    print("The estimated time for this process to complete is 2-3min.\n")
    ip = str(input("IP: "))
    print(f"Scanning 65.536 ports...\n")
    scanports(ip)

if __name__ == "__main__":
    main()