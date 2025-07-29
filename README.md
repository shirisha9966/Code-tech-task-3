# Code-tech-task-3
import socket
import threading
import requests
from base64 import b64encode

# ----------- MODULE 1: PORT SCANNER -----------
def port_scanner(target, ports=[21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]):
    print(f"\n[🔍] Scanning ports on {target}...")
    open_ports = []

    def scan(port):
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((target, port))
            print(f"  [✔] Port {port} is OPEN")
            open_ports.append(port)
            s.close()
        except:
            pass

    threads = []
    for port in ports:
        t = threading.Thread(target=scan, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if not open_ports:
        print("[✘] No open ports found.")
    return open_ports


# ----------- MODULE 2: BRUTE-FORCER (HTTP BASIC AUTH) -----------
def brute_force_http_auth(url, username_list, password_list):
    print(f"\n[🔐] Starting brute-force attack on {url} (Basic Auth)...")

    for username in username_list:
        for password in password_list:
            creds = f"{username}:{password}"
            encoded = b64encode(creds.encode()).decode()
            headers = {"Authorization": f"Basic {encoded}"}
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                print(f"[✔] Credentials Found: {username}:{password}")
                return (username, password)
            else:
                print(f"  [-] Tried: {username}:{password}")
    print("[✘] Brute-force failed. No valid credentials found.")
    return None


# ----------- MAIN TOOLKIT MENU -----------
def show_menu():
    print("\n" + "="*40)
    print("       PENETRATION TESTING TOOLKIT")
    print("="*40)
    print("1. Port Scanner")
    print("2. HTTP Basic Auth Brute-Force")
    print("3. Exit")

def main():
    while True:
        show_menu()
        choice = input("Select an option: ")

        if choice == "1":
            target = input("Enter target IP/hostname: ")
            port_scanner(target)

        elif choice == "2":
            url = input("Enter target URL (with http:// or https://): ")
            usernames = input("Enter usernames (comma-separated): ").split(",")
            passwords = input("Enter passwords (comma-separated): ").split(",")
            brute_force_http_auth(url, usernames, passwords)

        elif choice == "3":
            print("Exiting toolkit. Stay safe! 👋")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
