#!/usr/bin/env python3
import argparse
import sys
import json
import os
from pathlib import Path
from .engine import start_pipeline

# ======================
# Metadata
# ======================
TOOL_NAME = "NoN0IS3"
VERSION = "0.1.0"
CREATOR = "Sh4d0w"

# Cross-platform config directory
if os.name == 'nt':  # Windows
    CONFIG_DIR = Path(os.environ.get('APPDATA', Path.home())) / "nonoise"
else:  # Linux, macOS
    CONFIG_DIR = Path.home() / ".config" / "nonoise"

CONFIG_FILE = CONFIG_DIR / "config.json"

# ANSI color codes (work on most terminals)
GREEN = "\033[92m"
RED = "\033[91m"
DIM = "\033[2m"
RESET = "\033[0m"

# ======================
# Banner
# ======================
def print_banner():
    banner = f"""{GREEN}
 ____  _____        ____  _____   ____   _____   ______    ______  
|_   \\|_   _|      |_   \\|_   _|.'    '.|_   _|.' ____ \\  / ____ `.
  |   \\ | |   .--.   |   \\ | | |  .--.  | | |  | (___ \\_| `'  __) |
  | |\\ \\| | / .`\\ \\ | |\\ \\| | | |    | | | |   _.____`.  _  |__ '.
 _| |_\\   |_| \\__. |_| |_\\   |_|  `--'  |_| |_ | \\____) || \\____) |
|_____|\\____|'.__.'|_____|\\____|'.____.'|_____| \\______.' \\______.'
{RESET}
        {DIM}S I L E N T   R E C O N{RESET}
                                             {GREEN}{TOOL_NAME}{RESET} v{VERSION}
                                             Created by {RED}{CREATOR}{RESET}
"""
    print(banner)

# ======================
# Help / Manual
# ======================
def print_manual():
    print_banner()
    print("A passive-first reconnaissance tool focused on signal, not noise.")
    print("Designed to collect, filter, and prioritize attack-relevant URLs.\n")
    print("Usage:")
    print("  nonoise [options]\n")
    print("Examples:")
    print("  nonoise -d example.com")
    print("  nonoise -d example.com -w -t 50")
    print("  nonoise --interactive\n")
    print("Flags:")
    print("  -d,  --domain                 Target domain (example.com)")
    print("  -t,  --threads                Concurrent workers for URL visiting (default: 70)")
    print("  -w,  --wordpress              Enable WordPress-specific enumeration")
    print("  -sd, --skip-subdomains        Skip passive subdomain discovery")
    print("  -vapi,--virustotal-api        Set / update VirusTotal API key")
    print("  -sapi,--securitytrails-api    Set / update SecurityTrails API key")
    print("  -i,  --interactive            Start interactive mode")
    print("  -h,  --help                   Show this help")
    print("  -v,  --version                Show version\n")
    print("Notes:")
    print("  IMPORTANT: Enter the EXACT domain format you want to scan")
    print("       -If the site uses www.example.com → enter 'www.example.com'")
    print("       -If the site uses example.com → enter 'example.com'")
    print("       -Wrong format will break subdomain enumeration and scanning")
    print('Use "nonoise --help" for more information.')

# ======================
# Config
# ======================
def load_config():
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except json.JSONDecodeError:
            return {}
    return {}

def save_config(cfg):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def handle_api_keys(args):
    cfg = load_config()
    
    if args.virustotal_api:
        cfg["virustotal_api_key"] = args.virustotal_api
        save_config(cfg)
        print("[+] VirusTotal API key saved")
    
    if args.securitytrails_api:
        cfg["securitytrails_api_key"] = args.securitytrails_api
        save_config(cfg)
        print("[+] SecurityTrails API key saved")
    
    return cfg

# ======================
# Interactive Mode
# ======================
def interactive_mode():
    print_banner()
    print(f"{GREEN}[*] Interactive Mode{RESET}\n")
    
    # Get user input
    domain = input("Target domain (example.com): ").strip()
    
    if not domain:
        print("[!] Domain is required")
        sys.exit(1)
    
    wordpress_input = input("Is this WordPress? [y/N]: ").strip().lower()
    wordpress = wordpress_input.startswith("y")
    
    skip_subs_input = input("Skip subdomain discovery? [y/N]: ").strip().lower()
    skip_subs = skip_subs_input.startswith("y")
    
    threads_input = input("Threads for URL visiting [70]: ").strip()
    threads = int(threads_input) if threads_input else 70
    
    # Show equivalent CLI command
    print(f"\n{DIM}Equivalent CLI command:{RESET}")
    cmd = f"nonoise -d {domain} -t {threads}"
    if wordpress:
        cmd += " -w"
    if skip_subs:
        cmd += " -sd"
    print(f"{GREEN}{cmd}{RESET}\n")
    
    # Load config
    config = load_config()
    
    # Prepare data for engine
    user_data = {
        "domain": domain,
        "skip_subdomains": skip_subs,
        "wordpress_enabled": wordpress,
        "threads": threads,
        "config": config
    }
    
    print(f"[*] Target: {domain}")
    print(f"[*] Skip subdomains: {skip_subs}")
    print(f"[*] WordPress scan: {wordpress}")
    print(f"[*] URL visiting threads: {threads}")
    if wordpress:
        print(f"[*] WordPress uses fixed concurrency: 30")
    print()
    
    # Run pipeline
    try:
        output_path = start_pipeline(user_data)
        print(f"\n{GREEN}[✓] Complete! Results: {output_path}{RESET}")
    except KeyboardInterrupt:
        print(f"\n{DIM}[!] Interrupted{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

# ======================
# Main
# ======================
def main():
    # If no arguments, show manual
    if len(sys.argv) == 1:
        print_manual()
        sys.exit(0)
    
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-d", "--domain")
    parser.add_argument("-t", "--threads", type=int, default=70)
    parser.add_argument("-w", "--wordpress", action="store_true")
    parser.add_argument("-sd", "--skip-subdomains", action="store_true")
    parser.add_argument("-vapi", "--virustotal-api")
    parser.add_argument("-sapi", "--securitytrails-api")
    parser.add_argument("-i", "--interactive", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-v", "--version", action="store_true")
    
    args = parser.parse_args()
    
    if args.version:
        print(f"{TOOL_NAME} v{VERSION}")
        sys.exit(0)
    
    if args.help:
        print_manual()
        sys.exit(0)
    
    if args.interactive:
        interactive_mode()
        sys.exit(0)
    
    if not args.domain:
        print("[!] Error: domain is required\n")
        print_manual()
        sys.exit(1)
    
    print_banner()
    
    # Load config
    config = handle_api_keys(args)
    
    # Prepare data for engine
    user_data = {
        "domain": args.domain,
        "skip_subdomains": args.skip_subdomains,
        "wordpress_enabled": args.wordpress,
        "threads": args.threads,
        "config": config
    }
    
    print(f"[*] Target: {args.domain}")
    print(f"[*] Skip subdomains: {args.skip_subdomains}")
    print(f"[*] WordPress scan: {args.wordpress}")
    print(f"[*] URL visiting threads: {args.threads}")
    if args.wordpress:
        print(f"[*] WordPress uses fixed concurrency: 30")
    print()
    
    # Pass to engine
    try:
        output_path = start_pipeline(user_data)
        print(f"\n{GREEN}[✓] Complete! Results: {output_path}{RESET}")
    except KeyboardInterrupt:
        print(f"\n{DIM}[!] Interrupted{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
