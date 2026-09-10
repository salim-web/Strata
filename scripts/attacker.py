import os
import sys
import time
import random
import requests
from typing import List

# ANSI Color formatting
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

TARGET_BASE_URL = os.getenv("TARGET_BASE_URL", "http://localhost:8000")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "STRATAAttackerBot/2.0",
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Python-urllib/3.10"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "admin' UNION SELECT username, password FROM users--",
    "'; DROP TABLE logs;--",
    "1' OR '1'='1' --"
]

BRUTE_FORCE_PASSWORDS = [
    "123456", "password", "admin123", "letmein", "welcome", "secret123"
]

HONEYPOT_PATHS = [
    "/.env",
    "/wp-admin",
    "/wp-login.php",
    "/.git/config",
    "/api/v1/debug/secrets"
]


def print_status(method: str, path: str, status_code: int, detail: str = ""):
    if status_code == 200:
        color = GREEN
        tag = "[200 OK]"
    elif status_code == 429:
        color = YELLOW
        tag = "[429 RATE-LIMITED]"
    elif status_code in [403, 400, 401]:
        color = RED
        tag = f"[{status_code} BLOCKED/REJECTED]"
    else:
        color = RESET
        tag = f"[{status_code}]"

    msg = f"{color}{tag} {method} {path} - {detail}{RESET}"
    print(msg)


def simulate_ddos_flood(rate: int = 50, duration: int = 5):
    """
    High-velocity GET/POST burst to trigger sliding-window rate limiting (HTTP 429)
    and subsequent dynamic IP blacklisting (HTTP 403).
    """
    print(f"\n{CYAN}⚡ [DDoS Flood Simulation] Firing {rate} requests/sec for {duration} seconds...{RESET}")
    start_time = time.time()
    total_sent = 0
    blocked_or_throttled = 0

    while time.time() - start_time < duration:
        for _ in range(rate):
            total_sent += 1
            try:
                headers = {"User-Agent": random.choice(USER_AGENTS)}
                res = requests.get(f"{TARGET_BASE_URL}/api/v1/public/ping", headers=headers, timeout=1)
                if res.status_code in [429, 403]:
                    blocked_or_throttled += 1
                print_status("GET", "/api/v1/public/ping", res.status_code, f"Req #{total_sent}")
            except Exception as e:
                print(f"{RED}[Error] Connection failed: {e}{RESET}")
            time.sleep(1.0 / rate)

    print(f"{CYAN}Finished DDoS flood test. Total sent: {total_sent}, Throttled/Blocked: {blocked_or_throttled}{RESET}")


def simulate_sqli_attack():
    """
    Sends SQL injection vectors to /api/v1/search and /api/v1/auth/login.
    """
    print(f"\n{BLUE}🗡️ [SQL Injection Attack Simulation] Testing WAF detection...{RESET}")
    for payload in SQLI_PAYLOADS:
        random_ip = f"185.220.{random.randint(10, 240)}.{random.randint(1, 250)}"
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "X-Forwarded-For": random_ip
        }
        # Search target
        try:
            res = requests.get(f"{TARGET_BASE_URL}/api/v1/search", params={"q": payload}, headers=headers, timeout=2)
            print_status("GET", f"/api/v1/search?q={payload[:20]}...", res.status_code, f"IP: {random_ip} -> {res.text[:50]}")
        except Exception as e:
            print(f"{RED}[Error] {e}{RESET}")

        # Login target
        try:
            res = requests.post(f"{TARGET_BASE_URL}/api/v1/auth/login", json={"username": payload, "password": "123"}, headers=headers, timeout=2)
            print_status("POST", "/api/v1/auth/login", res.status_code, f"IP: {random_ip} -> {res.text[:50]}")
        except Exception as e:
            print(f"{RED}[Error] {e}{RESET}")


def simulate_brute_force():
    """
    Simulates rapid credential stuffing / brute-force dictionary attack on login endpoint.
    """
    random_ip = f"45.154.{random.randint(10, 240)}.{random.randint(1, 250)}"
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": random_ip
    }
    print(f"\n{YELLOW}🔑 [Brute-Force Attack Simulation] Attempting dictionary attack from {random_ip}...{RESET}")
    for pwd in BRUTE_FORCE_PASSWORDS:
        try:
            res = requests.post(
                f"{TARGET_BASE_URL}/api/v1/auth/login",
                json={"username": "admin", "password": pwd},
                headers=headers,
                timeout=2
            )
            print_status("POST", "/api/v1/auth/login", res.status_code, f"user=admin pwd={pwd}")
        except Exception as e:
            print(f"{RED}[Error] {e}{RESET}")
        time.sleep(0.1)


def simulate_honeypot_hit():
    """
    Probes honeypot endpoints to verify immediate 24-hour IP banning.
    """
    random_ip = f"91.240.{random.randint(10, 240)}.{random.randint(1, 250)}"
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": random_ip
    }
    print(f"\n{RED}🍯 [Honeypot Trap Probe Simulation] Hitting sensitive trap endpoints from {random_ip}...{RESET}")
    path = random.choice(HONEYPOT_PATHS)
    try:
        res = requests.get(f"{TARGET_BASE_URL}{path}", headers=headers, timeout=2)
        print_status("GET", path, res.status_code, res.text[:80])
    except Exception as e:
        print(f"{RED}[Error] {e}{RESET}")


def main():
    print("==================================================")
    print("🏴‍☠️ STRATA Attacker Simulation Suite v2.0")
    print(f"Targeting: {TARGET_BASE_URL}")
    print("Press Ctrl+C to terminate.")
    print("==================================================")

    iteration = 0
    try:
        while True:
            iteration += 1
            print(f"\n--- [Attack Wave #{iteration}] ---")

            # 1. SQL Injection Simulation
            simulate_sqli_attack()
            time.sleep(1)

            # 2. Brute-Force Dictionary Simulation
            simulate_brute_force()
            time.sleep(1)

            # 3. Honeypot Hit Simulation
            if iteration % 2 == 0:
                simulate_honeypot_hit()
                time.sleep(1)

            # 4. DDoS Flood Burst
            if iteration % 3 == 0:
                simulate_ddos_flood(rate=30, duration=3)

            print(f"\nWave #{iteration} complete. Pausing before next wave...")
            time.sleep(2)

    except KeyboardInterrupt:
        print(f"\n{GREEN}🛑 Attacker simulation terminated gracefully.{RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
