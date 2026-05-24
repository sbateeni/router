import subprocess
import sys
import os
import re
import json
import requests
from engines.utils import log

class SocialOSINT:
    """
    Social OSINT Engine — checks if an email or phone number is registered
    on various websites and social media platforms.
    Uses:
      - Holehe (Python lib) for email lookup across 100+ sites
      - Custom checks for phone-based social media (WhatsApp, Telegram, etc.)
      - Sherlock integration for username hunting
    """

    def __init__(self):
        self.results = {
            "email": {},
            "phone": {},
            "usernames_found": [],
            "profiles": []
        }

    # ──────────────────────────────────────────────
    #  EMAIL OSINT (using Holehe)
    # ──────────────────────────────────────────────
    def check_email(self, email):
        """Check which websites/social media an email is registered on using Holehe."""
        log(f"Starting Email OSINT for: {email}", "INFO")

        # Ensure holehe is installed
        try:
            import holehe
        except ImportError:
            log("Holehe not found. Installing...", "WARNING")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "holehe", "-q"])

        # Run holehe as a subprocess (it's designed as a CLI tool)
        try:
            cmd = [sys.executable, "-m", "holehe", email, "--csv", "--no-color"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=120)

            registered_sites = []
            not_registered = []

            for line in stdout.splitlines():
                line_clean = line.strip()
                # Holehe output format: [+] site.com
                if "[+]" in line_clean:
                    site = line_clean.replace("[+]", "").strip().split()[0] if line_clean.replace("[+]", "").strip() else ""
                    if site:
                        registered_sites.append(site)
                elif "[-]" in line_clean:
                    site = line_clean.replace("[-]", "").strip().split()[0] if line_clean.replace("[-]", "").strip() else ""
                    if site:
                        not_registered.append(site)

            self.results["email"] = {
                "target": email,
                "registered_on": registered_sites,
                "not_registered_on": not_registered
            }

            if registered_sites:
                log(f"Email '{email}' is REGISTERED on {len(registered_sites)} sites!", "SUCCESS")
                print("\n" + "="*60)
                print(f"  EMAIL OSINT RESULTS FOR: {email}")
                print("="*60)
                for i, site in enumerate(registered_sites):
                    print(f"  [+] {site}")
                print("="*60)
                print(f"  Total: {len(registered_sites)} sites found")
                print(f"  Checked: {len(registered_sites) + len(not_registered)} sites total")
                print("="*60)
            else:
                log(f"Email '{email}' was not found on any checked sites.", "INFO")

            return registered_sites

        except subprocess.TimeoutExpired:
            log("Holehe scan timed out after 120s.", "ERROR")
            return []
        except Exception as e:
            log(f"Email OSINT error: {e}", "ERROR")
            return []

    # ──────────────────────────────────────────────
    #  PHONE OSINT
    # ──────────────────────────────────────────────
    def check_phone(self, phone_number):
        """Check a phone number across social media and messaging platforms."""
        log(f"Starting Phone OSINT for: {phone_number}", "INFO")

        # Normalize phone number
        phone = phone_number.strip().replace(" ", "").replace("-", "")
        if not phone.startswith("+"):
            log("Tip: For best results, use international format like +966XXXXXXXXX", "WARNING")

        results = []

        # 1. WhatsApp check (via wa.me link — public availability check)
        log("  Checking WhatsApp...", "INFO")
        try:
            wa_url = f"https://wa.me/{phone.replace('+', '')}"
            resp = requests.get(wa_url, timeout=10, allow_redirects=True)
            if resp.status_code == 200 and "api.whatsapp.com" in resp.url:
                results.append({"platform": "WhatsApp", "status": "LIKELY REGISTERED", "url": wa_url})
                log("  [+] WhatsApp: Likely registered", "SUCCESS")
            else:
                log("  [-] WhatsApp: Not found or private", "INFO")
        except:
            pass

        # 2. Telegram check (via t.me)
        log("  Checking Telegram...", "INFO")
        try:
            tg_url = f"https://t.me/+{phone.replace('+', '')}"
            resp = requests.get(tg_url, timeout=10, allow_redirects=True)
            if resp.status_code == 200:
                results.append({"platform": "Telegram", "status": "POSSIBLE", "url": tg_url})
                log("  [+] Telegram: Possible account", "SUCCESS")
            else:
                log("  [-] Telegram: Not found", "INFO")
        except:
            pass

        # 3. Truecaller (basic — needs API for full results)
        log("  Checking Truecaller...", "INFO")
        try:
            tc_url = f"https://www.truecaller.com/search/{phone.replace('+', '')}"
            results.append({"platform": "Truecaller", "status": "CHECK MANUALLY", "url": tc_url})
            log(f"  [~] Truecaller: Check manually → {tc_url}", "INFO")
        except:
            pass

        # 4. Sync.me (reverse phone lookup)
        log("  Checking Sync.me...", "INFO")
        try:
            country_code = phone[1:4] if phone.startswith("+") else "1"
            number_part = phone[4:] if phone.startswith("+") else phone
            sync_url = f"https://sync.me/search/?number={phone.replace('+', '')}"
            results.append({"platform": "Sync.me", "status": "CHECK MANUALLY", "url": sync_url})
            log(f"  [~] Sync.me: Check manually → {sync_url}", "INFO")
        except:
            pass

        # Print summary
        if results:
            print("\n" + "="*60)
            print(f"  PHONE OSINT RESULTS FOR: {phone}")
            print("="*60)
            for r in results:
                status_icon = "[+]" if "REGISTERED" in r["status"] or "POSSIBLE" in r["status"] else "[~]"
                print(f"  {status_icon} {r['platform']:<15} | {r['status']:<20} | {r['url']}")
            print("="*60)

        self.results["phone"] = {
            "target": phone,
            "platforms": results
        }

        return results

    # ──────────────────────────────────────────────
    #  USERNAME HUNT (using Sherlock)
    # ──────────────────────────────────────────────
    def hunt_username(self, username):
        """Search for a username across 300+ social media sites using Sherlock."""
        log(f"Starting Username Hunt for: '{username}'", "INFO")

        # Check if sherlock is installed
        sherlock_path = None
        for path in ["sherlock", os.path.expanduser("~/.local/bin/sherlock")]:
            try:
                subprocess.run([path, "--version"], capture_output=True, timeout=5)
                sherlock_path = path
                break
            except:
                continue

        if not sherlock_path:
            log("Sherlock not found. Installing...", "WARNING")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "sherlock-project", "-q"])
                sherlock_path = "sherlock"
            except:
                log("Failed to install Sherlock. Skipping username hunt.", "ERROR")
                return []

        try:
            # Run sherlock
            output_dir = "targets/osint"
            os.makedirs(output_dir, exist_ok=True)

            cmd = [sherlock_path, username, "--print-found", "--no-color", "--timeout", "10"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=180)

            found_profiles = []
            for line in stdout.splitlines():
                line = line.strip()
                # Sherlock output: [+] SiteName: https://url
                if "[+]" in line or "http" in line:
                    # Extract URL
                    url_match = re.search(r'https?://\S+', line)
                    if url_match:
                        url = url_match.group()
                        site_name = line.split(":")[0].replace("[+]", "").replace("[*]", "").strip()
                        found_profiles.append({"site": site_name, "url": url})

            if found_profiles:
                log(f"Found {len(found_profiles)} profiles for username '{username}'!", "SUCCESS")
                print("\n" + "="*60)
                print(f"  USERNAME HUNT RESULTS FOR: '{username}'")
                print("="*60)
                for p in found_profiles:
                    print(f"  [+] {p['site']:<20} → {p['url']}")
                print("="*60)

                self.results["profiles"] = found_profiles
            else:
                log(f"No profiles found for username '{username}'.", "INFO")

            return found_profiles

        except subprocess.TimeoutExpired:
            log("Sherlock timed out after 180s.", "ERROR")
            return []
        except Exception as e:
            log(f"Username hunt error: {e}", "ERROR")
            return []

    def save_results(self, filename="targets/osint/social_osint_report.json"):
        """Save all OSINT results to a JSON file."""
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=4, ensure_ascii=False)
        log(f"OSINT report saved to: {filename}", "SUCCESS")


def run_social_osint_menu():
    """Interactive menu for Social OSINT operations."""
    osint = SocialOSINT()

    while True:
        print("\n" + "="*50)
        print("      SOCIAL OSINT ENGINE")
        print("="*50)
        print("  [1] Check Email (find registered sites)")
        print("  [2] Check Phone Number (WhatsApp, Telegram...)")
        print("  [3] Hunt Username (300+ social media sites)")
        print("  [4] Full Investigation (Email + Username)")
        print("  [0] Back to Main Menu")
        print("="*50)

        choice = input("\n[?] Select option: ").strip()

        if choice == '0':
            break
        elif choice == '1':
            email = input("[?] Enter Email Address: ").strip()
            if email:
                osint.check_email(email)
        elif choice == '2':
            phone = input("[?] Enter Phone Number (e.g., +966XXXXXXXXX): ").strip()
            if phone:
                osint.check_phone(phone)
        elif choice == '3':
            username = input("[?] Enter Username to hunt: ").strip()
            if username:
                osint.hunt_username(username)
        elif choice == '4':
            email = input("[?] Enter Email Address: ").strip()
            if email:
                sites = osint.check_email(email)
                # Extract potential username from email
                username = email.split("@")[0]
                log(f"Extracted username from email: '{username}'. Hunting...", "INFO")
                osint.hunt_username(username)
        else:
            log("Invalid option.", "ERROR")

    # Save report
    if any(osint.results[k] for k in osint.results):
        osint.save_results()

    return osint.results


if __name__ == "__main__":
    run_social_osint_menu()
