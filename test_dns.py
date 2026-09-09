"""
Test DNS Resolution - Debug Tool
"""

import dns.resolver
import socket
import time
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def test_dns(domain):
    """Test DNS resolution for a domain"""
    print(f"\n{'='*50}")
    print(f"[*] Testing DNS resolution for: {domain}")
    print('='*50)
    
    # Test 1: Socket resolution
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] socket.gethostbyname: {ip}")
    except Exception as e:
        print(f"[-] socket.gethostbyname error: {e}")
    
    # Test 2: dnspython with default resolver
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            print(f"[+] dnspython (default): {rdata}")
    except Exception as e:
        print(f"[-] dnspython error: {e}")
    
    # Test 3: dnspython with Google DNS
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8']
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            print(f"[+] dnspython (Google DNS): {rdata}")
    except Exception as e:
        print(f"[-] Google DNS error: {e}")
    
    # Test 4: dnspython with Cloudflare DNS
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['1.1.1.1']
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            print(f"[+] dnspython (Cloudflare): {rdata}")
    except Exception as e:
        print(f"[-] Cloudflare DNS error: {e}")

def test_subdomain(domain, subdomain):
    """Test a specific subdomain"""
    full_domain = f"{subdomain}.{domain}"
    print(f"\n{'*'*50}")
    print(f"[*] Testing subdomain: {full_domain}")
    print('*'*50)
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        resolver.timeout = 3.0
        resolver.lifetime = 3.0
        
        answers = resolver.resolve(full_domain, 'A')
        for rdata in answers:
            print(f"[+] {full_domain} -> {rdata}")
    except dns.resolver.NXDOMAIN:
        print(f"[-] {full_domain} does not exist")
    except dns.resolver.NoAnswer:
        print(f"[-] {full_domain} has no A record")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    print(f"""
{Fore.CYAN}
╔═══════════════════════════════════════════╗
║        DNS TEST TOOL                      ║
║        Debug DNS Resolution Issues        ║
╚═══════════════════════════════════════════╝{Style.RESET_ALL}
    """)
    
    # Test with known good domain
    test_dns("google.com")
    
    # Test with the target domain
    domain = input(f"\n{Fore.YELLOW}[?] Enter your target domain (e.g., google.com): {Style.RESET_ALL}")
    if domain:
        test_dns(domain)
        
        # Test with a random subdomain
        import random
        import string
        random_sub = ''.join(random.choices(string.ascii_lowercase, k=8))
        test_subdomain(domain, random_sub)
        
        # Test with common subdomains
        test_subdomain(domain, "www")
        test_subdomain(domain, "mail")
        test_subdomain(domain, "admin")