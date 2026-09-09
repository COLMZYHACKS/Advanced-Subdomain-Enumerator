#!/usr/bin/env python3
"""
Advanced Subdomain Enumerator
Author: D4RK-D43mon
Description: Multi-threaded subdomain enumeration with DNS resolution, HTTP probing,
             wildcard detection, and certificate transparency logs
"""

import sys
import os
import time
import json
import csv
from datetime import datetime
from colorama import init, Fore, Style
from tabulate import tabulate
from tqdm import tqdm

from modules.dns_resolver import DNSResolver
from modules.http_prober import HTTPProber

# Initialize colorama
init(autoreset=True)

class SubdomainEnumerator:
    """Main subdomain enumeration class"""
    
    def __init__(self, domain, wordlist_path, threads=50, timeout=3.0):
        """
        Initialize the enumerator
        
        Args:
            domain: Target domain
            wordlist_path: Path to subdomain wordlist
            threads: Number of threads for scanning
            timeout: DNS timeout in seconds
        """
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.timeout = timeout
        
        # Results storage
        self.dns_results = []
        self.http_results = []
        self.final_results = []
        
        # Initialize modules
        self.dns_resolver = DNSResolver(domain, timeout)
        self.http_prober = HTTPProber(timeout)
        
        # Timing
        self.start_time = None
        self.end_time = None
        
    def load_wordlist(self):
        """
        Load subdomain wordlist from file
        
        Returns:
            List of subdomains
        """
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            return subdomains
        except FileNotFoundError:
            print(f"{Fore.RED}[-] Wordlist not found: {self.wordlist_path}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading wordlist: {e}")
            sys.exit(1)
    
    def enumerate(self):
        """Run the full enumeration process"""
        print(f"""
{Fore.CYAN}
╔═══════════════════════════════════════════════════════════╗
║        ADVANCED SUBDOMAIN ENUMERATOR v2.0                 ║
║        Developed by: D4RK-D43mon                          ║
║        Smart Enumeration | Live Probing | Intelligence    ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """)
        
        print(f"{Fore.CYAN}[*] Target: {self.domain}")
        print(f"[*] Wordlist: {self.wordlist_path}")
        print(f"[*] Threads: {self.threads}")
        print(f"[*] Timeout: {self.timeout} seconds")
        
        # Load wordlist
        subdomains = self.load_wordlist()
        print(f"[*] Loaded {len(subdomains)} subdomains")
        
        # Debug: Show first few subdomains
        print(f"{Fore.CYAN}[DEBUG] First 10 subdomains:")
        for sub in subdomains[:10]:
            print(f"  - {sub}")
        
        # Check for wildcard DNS
        print(f"\n{Fore.YELLOW}[*] Checking for wildcard DNS...")
        has_wildcard = self.dns_resolver.detect_wildcard()
        if has_wildcard:
            print(f"{Fore.YELLOW}[!] Wildcard DNS detected! Filtering wildcard results...")
        else:
            print(f"{Fore.GREEN}[+] No wildcard DNS detected.")
        
        # Start enumeration
        print(f"\n{Fore.CYAN}[*] Starting DNS enumeration...")
        print("-" * 60)
        
        self.start_time = time.time()
        
        # DNS resolution with progress bar
        dns_results = []
        
        # Use tqdm for progress bar
        with tqdm(total=len(subdomains), desc="Resolving DNS", unit="subdomains") as pbar:
            # Process in smaller batches to avoid overwhelming
            batch_size = min(500, len(subdomains))
            total_batches = (len(subdomains) + batch_size - 1) // batch_size
            
            for batch_num in range(total_batches):
                start_idx = batch_num * batch_size
                end_idx = min(start_idx + batch_size, len(subdomains))
                batch = subdomains[start_idx:end_idx]
                
                # Resolve batch
                batch_results = self.dns_resolver.resolve_batch(batch, self.threads)
                dns_results.extend(batch_results)
                
                # Update progress bar
                pbar.update(len(batch))
                
                # Print batch progress
                print(f"\n{Fore.CYAN}[*] Batch {batch_num+1}/{total_batches} complete. Found {len([r for r in batch_results if r['resolved']])} subdomains.")
        
        self.dns_results = dns_results
        
        # Filter out wildcard results
        valid_dns = [r for r in dns_results if r['resolved'] and not r['is_wildcard']]
        
        print(f"\n{Fore.GREEN}[+] DNS resolution complete!")
        print(f"[+] Found {len(valid_dns)} valid subdomains (excluding wildcards)")
        
        # HTTP probing
        if valid_dns:
            print(f"\n{Fore.CYAN}[*] Starting HTTP probing...")
            print("-" * 60)
            
            subdomain_list = [r['subdomain'] for r in valid_dns]
            
            with tqdm(total=len(subdomain_list), desc="Probing HTTP", unit="subdomains") as pbar:
                # Process in smaller batches for HTTP too
                batch_size = min(100, len(subdomain_list))
                total_batches = (len(subdomain_list) + batch_size - 1) // batch_size
                
                for batch_num in range(total_batches):
                    start_idx = batch_num * batch_size
                    end_idx = min(start_idx + batch_size, len(subdomain_list))
                    batch = subdomain_list[start_idx:end_idx]
                    
                    batch_results = self.http_prober.probe_batch(batch, self.threads)
                    self.http_results.extend(batch_results)
                    pbar.update(len(batch))
            
            # Merge DNS and HTTP results
            for dns_result in valid_dns:
                subdomain = dns_result['subdomain']
                http_result = next(
                    (h for h in self.http_results if h['subdomain'] == subdomain),
                    None
                )
                
                merged = {
                    'subdomain': subdomain,
                    'ip': dns_result['ip'],
                    'cname': dns_result['cname'],
                    'status_code': http_result['status_code'] if http_result else None,
                    'title': http_result['title'] if http_result else None,
                    'server': http_result['server'] if http_result else None,
                    'is_live': http_result['is_live'] if http_result else False,
                    'url': http_result['url'] if http_result else None
                }
                self.final_results.append(merged)
        
        self.end_time = time.time()
        
        # Display results
        self.display_results()
        
        # Export results
        self.export_results()
    
    def display_results(self):
        """Display enumeration results in a table"""
        elapsed = self.end_time - self.start_time
        
        print("\n" + "=" * 80)
        print(f"{Fore.GREEN} SUBDOMAIN ENUMERATION COMPLETE")
        print(f"{Fore.CYAN} Target: {self.domain}")
        print(f"{Fore.CYAN} Total Subdomains Found: {len(self.final_results)}")
        print(f"{Fore.CYAN} Active Subdomains: {len([r for r in self.final_results if r['is_live']])}")
        print(f"{Fore.CYAN} Time taken: {elapsed:.2f} seconds")
        print("=" * 80)
        
        if not self.final_results:
            print(f"\n{Fore.YELLOW}[!] No subdomains found.")
            print(f"{Fore.YELLOW}[!] Try increasing threads, timeout, or using a larger wordlist.")
            return
        
        # Prepare table data
        table_data = []
        
        for result in sorted(self.final_results, key=lambda x: x['subdomain']):
            # Status color
            status_code = result['status_code']
            if status_code:
                if 200 <= status_code < 300:
                    status = f"{Fore.GREEN}{status_code}{Style.RESET_ALL}"
                elif 300 <= status_code < 400:
                    status = f"{Fore.CYAN}{status_code}{Style.RESET_ALL}"
                elif 400 <= status_code < 500:
                    status = f"{Fore.YELLOW}{status_code}{Style.RESET_ALL}"
                else:
                    status = f"{Fore.RED}{status_code}{Style.RESET_ALL}"
            else:
                status = f"{Fore.RED}N/A{Style.RESET_ALL}"
            
            table_data.append([
                result['subdomain'],
                result['ip'] or 'N/A',
                status,
                result['title'] or 'N/A',
                result['server'] or 'N/A'
            ])
        
        # Show top results (limit to 20 for readability)
        display_count = min(20, len(table_data))
        print(f"\n{Fore.CYAN} TOP {display_count} RESULTS:")
        print("-" * 80)
        
        headers = ["Subdomain", "IP Address", "Status", "Title", "Server"]
        print(tabulate(table_data[:display_count], headers=headers, tablefmt="grid"))
        
        if len(table_data) > 20:
            print(f"\n{Fore.CYAN}[!] Showing first 20 of {len(table_data)} results.")
            print(f"[!] Full results available in exported files.")
        
        print("-" * 80)
    
    def export_results(self):
        """Export results to multiple formats"""
        if not self.final_results:
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain_clean = self.domain.replace('.', '_')
        
        # Create outputs directory if it doesn't exist
        os.makedirs('outputs', exist_ok=True)
        
        # Export to JSON
        json_file = f"outputs/{domain_clean}_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.final_results, f, indent=2)
        print(f"\n{Fore.GREEN}[+] JSON results saved to: {json_file}")
        
        # Export to CSV
        csv_file = f"outputs/{domain_clean}_{timestamp}.csv"
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            if self.final_results:
                writer = csv.DictWriter(f, fieldnames=self.final_results[0].keys())
                writer.writeheader()
                writer.writerows(self.final_results)
        print(f"{Fore.GREEN}[+] CSV results saved to: {csv_file}")
        
        # Export to text file
        txt_file = f"outputs/{domain_clean}_{timestamp}.txt"
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("SUBDOMAIN ENUMERATION REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Target: {self.domain}\n")
            f.write(f"Date: {datetime.now()}\n")
            f.write(f"Total Subdomains Found: {len(self.final_results)}\n")
            f.write("-" * 80 + "\n\n")
            
            for result in sorted(self.final_results, key=lambda x: x['subdomain']):
                f.write(f"Subdomain: {result['subdomain']}\n")
                f.write(f"IP Address: {result['ip'] or 'N/A'}\n")
                f.write(f"CNAME: {result['cname'] or 'N/A'}\n")
                f.write(f"Status: {result['status_code'] or 'N/A'}\n")
                f.write(f"Title: {result['title'] or 'N/A'}\n")
                f.write(f"Server: {result['server'] or 'N/A'}\n")
                f.write(f"Live: {result['is_live']}\n")
                f.write("-" * 40 + "\n")
        
        print(f"{Fore.GREEN}[+] Text results saved to: {txt_file}")

def main():
    """Main entry point"""
    
    print(f"""
{Fore.CYAN}
╔═══════════════════════════════════════════════════════════╗
║        ADVANCED SUBDOMAIN ENUMERATOR v2.0                 ║
║        Developed by: D4RK-D43mon                          ║
║        Smart Enumeration | Live Probing | Intelligence    ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """)
    
    # Get target domain
    domain = input(f"{Fore.YELLOW}[?] Enter target domain (e.g., example.com): {Style.RESET_ALL}")
    
    if not domain:
        print(f"{Fore.RED}[-] No domain specified. Exiting.")
        sys.exit(1)
    
    # Clean domain
    domain = domain.strip().lower()
    
    # Get wordlist path
    wordlist_path = input(f"{Fore.YELLOW}[?] Path to wordlist (default: wordlists/subdomains.txt): {Style.RESET_ALL}")
    if not wordlist_path:
        wordlist_path = "wordlists/subdomains.txt"
    
    # Get threads
    threads_input = input(f"{Fore.YELLOW}[?] Number of threads (default: 20, recommended: 10-20): {Style.RESET_ALL}")
    threads = int(threads_input) if threads_input else 20
    
    # Get timeout
    timeout_input = input(f"{Fore.YELLOW}[?] DNS timeout in seconds (default: 5.0, recommended: 5-10): {Style.RESET_ALL}")
    timeout = float(timeout_input) if timeout_input else 5.0
    
    # Confirm
    print(f"\n{Fore.CYAN}[*] Configuration:")
    print(f"    Domain: {domain}")
    print(f"    Wordlist: {wordlist_path}")
    print(f"    Threads: {threads}")
    print(f"    Timeout: {timeout}s")
    
    confirm = input(f"\n{Fore.YELLOW}[?] Start enumeration? (y/n): {Style.RESET_ALL}")
    if confirm.lower() != 'y':
        print(f"{Fore.YELLOW}[!] Enumeration cancelled.")
        sys.exit(0)
    
    # Run enumeration
    try:
        enumerator = SubdomainEnumerator(domain, wordlist_path, threads, timeout)
        enumerator.enumerate()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Enumeration interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()