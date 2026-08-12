import socket
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

def scan_port(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            return port
    except socket.error:
        pass
    finally:
        sock.close()
    return None

def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"

def scan_ports(target, start_port, end_port, timeout, workers):
    open_ports = []
    print("\nStarting scan...")
    print("Target :", target)
    print("Ports  :", f"{start_port}-{end_port}")
    print("-" * 50)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        for port in range(start_port, end_port + 1):
            future = executor.submit(scan_port, target, port, timeout)
            futures.append(future)
        for future in futures:
            port = future.result()
            if port is not None:
                service = get_service_name(port)
                open_ports.append((port, service))
                print(f"[+] {port:<6} OPEN     {service}")
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="TCP Network Port Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", nargs=2, type=int, metavar=("START", "END"), default=[1, 1000], help="Port range to scan")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="Connection timeout")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Number of threads")
    args = parser.parse_args()
    target = args.target
    start_port = args.ports[0]
    end_port = args.ports[1]

    if start_port < 1 or start_port > 65535:
        parser.error("Invalid starting port")
    if end_port < 1 or end_port > 65535:
        parser.error("Invalid ending port")
    if start_port > end_port:
        parser.error("Starting port must be smaller than ending port")

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Could not resolve target:", target)
        return

    print("=" * 50)
    print("        PYTHON NETWORK PORT SCANNER")
    print("=" * 50)
    print("Hostname :", target)
    print("IP       :", target_ip)

    start_time = datetime.now()
    open_ports = scan_ports(target_ip, start_port, end_port, args.timeout, args.workers)
    end_time = datetime.now()
    duration = end_time - start_time

    print("-" * 50)
    if len(open_ports) > 0:
        print("Open ports found:", len(open_ports))
        with open("scan_results.txt", "w") as file:
            file.write("Target: " + target + "\n")
            file.write("Ports: " + str(start_port) + "-" + str(end_port) + "\n\n")
            for port, service in open_ports:
                file.write(str(port) + "/tcp - OPEN - " + service + "\n")
        print("Results saved to scan_results.txt")
    else:
        print("No open TCP ports found.")

    print("Scan completed in:", round(duration.total_seconds(), 2), "seconds")

if __name__ == "__main__":
    main()


