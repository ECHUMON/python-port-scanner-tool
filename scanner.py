import socket
from concurrent.futures import ThreadPoolExecutor


COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP Alternate",
}


def get_service_name(port):
    return COMMON_SERVICES.get(port, "Unknown")


def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        result = sock.connect_ex((ip, port))
        sock.close()

        status = "OPEN" if result == 0 else "CLOSED"

        return {
            "Port": port,
            "Service": get_service_name(port),
            "Status": status
        }

    except:
        return {
            "Port": port,
            "Service": get_service_name(port),
            "Status": "CLOSED"
        }


def scan_ports(ip, ports):
    results = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(lambda port: scan_port(ip, port), ports))

    return results