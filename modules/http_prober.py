"""
HTTP Probing Module
Checks if subdomains respond to HTTP/HTTPS requests
"""

import requests
import threading
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class HTTPProber:
    """Probes subdomains for HTTP/HTTPS services"""
    
    def __init__(self, timeout=5.0, verify_ssl=False):
        """
        Initialize HTTP prober
        
        Args:
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.timeout = timeout
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.lock = threading.Lock()
    
    def probe_subdomain(self, subdomain):
        """
        Probe a subdomain for HTTP/HTTPS
        
        Args:
            subdomain: Full subdomain (e.g., admin.example.com)
            
        Returns:
            dict: {
                'subdomain': str,
                'url': str,
                'status_code': int or None,
                'title': str or None,
                'server': str or None,
                'content_type': str or None,
                'is_live': bool,
                'error': str or None
            }
        """
        result = {
            'subdomain': subdomain,
            'url': None,
            'status_code': None,
            'title': None,
            'server': None,
            'content_type': None,
            'is_live': False,
            'error': None
        }
        
        # Try HTTPS first, then HTTP
        protocols = ['https', 'http']
        
        for protocol in protocols:
            url = f"{protocol}://{subdomain}"
            result['url'] = url
            
            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                
                result['status_code'] = response.status_code
                result['content_type'] = response.headers.get('Content-Type', '').split(';')[0]
                result['server'] = response.headers.get('Server', 'Unknown')
                
                # Extract title from HTML
                if 'text/html' in response.headers.get('Content-Type', ''):
                    title = self.extract_title(response.text)
                    if title:
                        result['title'] = title
                
                # Consider 2xx, 3xx, 4xx as "live" (except 404)
                if response.status_code < 500:
                    result['is_live'] = True
                    break
                    
            except requests.exceptions.ConnectionError:
                # Try next protocol or mark as unreachable
                continue
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.SSLError:
                # Try with verify=False
                try:
                    response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                    result['status_code'] = response.status_code
                    result['content_type'] = response.headers.get('Content-Type', '').split(';')[0]
                    result['server'] = response.headers.get('Server', 'Unknown')
                    if 'text/html' in response.headers.get('Content-Type', ''):
                        title = self.extract_title(response.text)
                        if title:
                            result['title'] = title
                    if response.status_code < 500:
                        result['is_live'] = True
                        break
                except:
                    continue
            except Exception:
                continue
        
        return result
    
    def extract_title(self, html):
        """Extract title from HTML content"""
        import re
        try:
            match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()
                # Clean up extra whitespace
                title = re.sub(r'\s+', ' ', title)
                return title[:100]  # Limit length
        except:
            pass
        return None
    
    def probe_batch(self, subdomains, max_workers=20):
        """
        Probe multiple subdomains using threading
        
        Args:
            subdomains: List of subdomains to probe
            max_workers: Maximum concurrent threads
            
        Returns:
            List of probe results
        """
        results = []
        import concurrent.futures
        
        if not subdomains:
            return results
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_subdomain = {
                executor.submit(self.probe_subdomain, subdomain): subdomain 
                for subdomain in subdomains
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                try:
                    result = future.result(timeout=10)
                    results.append(result)
                except concurrent.futures.TimeoutError:
                    pass
                except Exception:
                    pass
        
        return results