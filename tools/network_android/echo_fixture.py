"""Bounded LAN fixture for the attached phone. Synthetic data only; no external services."""
import argparse
import socket
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument("--bind", required=True)
parser.add_argument("--seconds", type=int, default=600)
args = parser.parse_args()
stop = threading.Event()
sockets = []

def tcp():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.bind, 39080))
    server.listen(8)
    server.settimeout(1)
    sockets.append(server)
    while not stop.is_set():
        try:
            client, _ = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        with client:
            client.settimeout(10)
            try:
                while data := client.recv(16384):
                    client.sendall(data)
            except (socket.timeout, OSError):
                pass

def udp(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((args.bind, port))
    server.settimeout(1)
    sockets.append(server)
    while not stop.is_set():
        try:
            data, address = server.recvfrom(65535)
            server.sendto(data, address)
        except socket.timeout:
            continue
        except OSError:
            break

threads = [threading.Thread(target=tcp, daemon=True)] + [
    threading.Thread(target=udp, args=(port,), daemon=True) for port in range(39090, 39102)]
for thread in threads:
    thread.start()
print("Synthetic TCP/UDP echo fixture ready", flush=True)
try:
    time.sleep(args.seconds)
finally:
    stop.set()
    for item in sockets:
        item.close()
