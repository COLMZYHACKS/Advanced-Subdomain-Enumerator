"""
DNS Resolution Module
Handles subdomain resolution with wildcard detection
"""

import dns.resolver
import dns.exception
import socket
import threading
import time
from colorama import Fore, Style

class DNSResolver:
    """Handles DNS resolution for subdomains"""
    
    def __init__(self, domain, timeout=3.0):
        """
        Initialize DNS resolver
        
        Args:
            domain: Target domain (e.g., example.com)
            timeout: DNS query timeout in seconds
        """
        self.domain = domain
        self.timeout = timeout
        self.wildcard_ip = None
        self.wildcard_detected = False
        
        # Create resolver with custom DNS servers
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Use multiple DNS servers for reliability
        self.resolver.nameservers = [
            '8.8.8.8',      # Google DNS Primary
            '1.1.1.1',      # Cloudflare DNS
            '8.8.4.4',      # Google DNS Secondary
            '9.9.9.9',      # Quad9 DNS
            '208.67.222.222' # OpenDNS
        ]
        
        # Lock for thread safety
        self.lock = threading.Lock()
        self.resolved_count = 0
    
    def detect_wildcard(self):
        """
        Detect if wildcard DNS is enabled for the domain
        Example: *.example.com resolves to the same IP for any subdomain
        """
        try:
            # Test a random subdomain that shouldn't exist
            import random
            import string
            random_string = ''.join(random.choices(string.ascii_lowercase, k=10))
            test_subdomain = f"{random_string}.{self.domain}"
            
            try:
                answers = self.resolver.resolve(test_subdomain, 'A')
                
                if answers:
                    # Wildcard detected - all subdomains resolve to this IP
                    self.wildcard_ip = str(answers[0])
                    self.wildcard_detected = True
                    print(f"{Fore.YELLOW}[!] Wildcard detected: *.{self.domain} -> {self.wildcard_ip}")
                    return True
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                # No wildcard (good!)
                return False
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Wildcard detection error: {e}")
                return False
                
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Wildcard detection failed: {e}")
            return False
    
    def resolve_subdomain(self, subdomain):
        """
        Resolve a subdomain to its IP address
        
        Args:
            subdomain: Subdomain to resolve (e.g., admin)
            
        Returns:
            dict: {
                'subdomain': str,
                'ip': str or None,
                'cname': str or None,
                'resolved': bool,
                'is_wildcard': bool
            }
        """
        full_domain = f"{subdomain}.{self.domain}"
        
        result = {
            'subdomain': full_domain,
            'ip': None,
            'cname': None,
            'resolved': False,
            'is_wildcard': False
        }
        
        try:
            # Try to resolve A record with timeout
            answers = self.resolver.resolve(full_domain, 'A')
            
            if answers:
                ip = str(answers[0])
                result['ip'] = ip
                result['resolved'] = True
                
                # Check if this is a wildcard
                if self.wildcard_detected and ip == self.wildcard_ip:
                    result['is_wildcard'] = True
                
                # Try to get CNAME (if any)
                try:
                    cname_answers = self.resolver.resolve(full_domain, 'CNAME')
                    if cname_answers:
                        result['cname'] = str(cname_answers[0].target).rstrip('.')
                except:
                    pass
                    
        except dns.resolver.NXDOMAIN:
            # Subdomain doesn't exist - skip quietly
            pass
        except dns.resolver.NoAnswer:
            # No A record - skip quietly
            pass
        except dns.exception.Timeout:
            # Timeout - log occasionally
            pass
        except Exception as e:
            # Other errors - log occasionally
            pass
            
        return result
    
    def resolve_batch(self, subdomains, max_workers=20):
        """
        Resolve multiple subdomains using threading
        
        Args:
            subdomains: List of subdomains to resolve
            max_workers: Maximum concurrent threads
            
        Returns:
            List of resolution results
        """
        results = []
        import concurrent.futures
        
        if not subdomains:
            return results
        
        # Process in smaller batches to avoid overwhelming
        batch_size = min(200, len(subdomains))
        total_batches = (len(subdomains) + batch_size - 1) // batch_size
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for batch_num in range(total_batches):
                start_idx = batch_num * batch_size
                end_idx = min(start_idx + batch_size, len(subdomains))
                batch = subdomains[start_idx:end_idx]
                
                # Submit batch
                future_to_subdomain = {
                    executor.submit(self.resolve_subdomain, subdomain): subdomain 
                    for subdomain in batch
                }
                
                # Collect results for this batch with timeout
                completed = 0
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    try:
                        result = future.result(timeout=10)
                        if result['resolved']:
                            results.append(result)
                        completed += 1
                        
                        # Print progress every 100 results
                        if completed % 100 == 0:
                            print(f"\r{Fore.CYAN}[*] Resolved {completed}/{len(batch)} in batch {batch_num+1}/{total_batches}", end='')
                            
                    except concurrent.futures.TimeoutError:
                        pass
                    except Exception:
                        pass
                
                # Print batch completion
                found_in_batch = len([r for r in results if r['resolved']])
                print(f"\n{Fore.CYAN}[*] Batch {batch_num+1}/{total_batches} complete. Found {found_in_batch} so far.")
        
        return results
    
    def resolve_batch_single_threaded(self, subdomains):
        """
        Resolve subdomains one by one (for debugging)
        """
        results = []
        
        for i, subdomain in enumerate(subdomains):
            result = self.resolve_subdomain(subdomain)
            if result['resolved']:
                results.append(result)
            
            # Print progress
            if i % 100 == 0:
                print(f"{Fore.CYAN}[*] Progress: {i}/{len(subdomains)}")
        
        return results