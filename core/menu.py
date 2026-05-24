CLASSIC_CHOICES = set(range(1, 11))
AI_CHOICES = {11, 12, 13, 14}
RECON_CHOICES = {16, 17, 18, 19}
ENGINE_CHOICES = {21}


def select_tool_menu():
    print("\nAvailable tools:")
    print("  1) All tools (full scan — classic only, no AI)")
    print("")
    print("  Classic tools (individual):")
    print("  2) Nmap scan only")
    print("  3) Nuclei only")
    print("  4) Dirsearch only")
    print("  5) SQLMap only")
    print("  6) RouterSploit only")
    print("  7) Ingram only")
    print("  8) Hydra only")
    print("  9) FFUF only")
    print(" 10) GAU only")
    print("")
    print("  AI tools (individual — separate from classic):")
    print(" 11) AI scan plan only (Nmap + tool selection)")
    print(" 12) AI Hydra commands only (Nmap + Hydra plan)")
    print(" 13) AI RouterSploit + follow-up modules")
    print(" 14) AI final report only (from existing scan data)")
    print("")
    print("  Extra recon tools:")
    print(" 16) LAN network discovery (find live hosts)")
    print(" 17) Nikto web scan only")
    print(" 18) WhatWeb fingerprint only")
    print(" 19) Nmap vuln scripts only")
    print("")
    print(" 20) Exit")

    valid_choices = {str(i) for i in list(range(1, 15)) + [16, 17, 18, 19, 20]}
    while True:
        choice = input("Select an option [1-20]: ").strip()
        if choice in valid_choices:
            return int(choice)
        print("Please enter a valid option number.")
