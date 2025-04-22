#!/usr/bin/env python3

import argparse
import concurrent.futures
import difflib
import json
import os
import random
import re
import string
import subprocess
import sys
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin

import requests
from requests.exceptions import RequestException
from colorama import Fore, Style, init
from tqdm import tqdm

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

# Constants
VERSION = "2.0"  # Updated version
DEFAULT_THREADS = 10
DEFAULT_DELAY = 1
DEFAULT_TIMEOUT = 10
DEFAULT_RETRIES = 3
MAX_URLS = 1000
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"

# Color definitions
COLORS = {
    "RED": Fore.RED,
    "GREEN": Fore.GREEN,
    "YELLOW": Fore.YELLOW,
    "BLUE": Fore.BLUE,
    "MAGENTA": Fore.MAGENTA,
    "CYAN": Fore.CYAN,
    "RESET": Style.RESET_ALL,
    "BOLD": Style.BRIGHT,
    "DIM": Style.DIM
}

# Terminal width for formatting
try:
    TERM_WIDTH = os.get_terminal_size().columns
except OSError:
    TERM_WIDTH = 100  # Default if terminal width detection fails

# Progress bar formatting
PROGRESS_BAR_FORMAT = "{desc:<25.25}{percentage:3.0f}%|{bar:40}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
SUB_PROGRESS_BAR_FORMAT = "   ├─ {desc:<22.22}{percentage:3.0f}%|{bar:30}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
FINAL_PROGRESS_BAR_FORMAT = "   └─ {desc:<22.22}{percentage:3.0f}%|{bar:30}| {n_fmt}/{total_fmt} [{elapsed}, {rate_fmt}]"

def show_banner():
    """Display the program banner"""
    banner_width = min(80, TERM_WIDTH)
    print(f"{COLORS['CYAN']}{'═'*banner_width}")
    print(f"║ Cache Poisoning Scanner v{VERSION} {' '*(banner_width-41)}")
    print(f"║ Advanced Web Cache Vulnerability Detection - Created by Joel Indra {' '*(banner_width-40)}")
    print(f"{'═'*banner_width}{COLORS['RESET']}\n")

def log(level, message):
    """Log messages with timestamp and color coding - with improved alignment"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    level_display = {
        "INFO": f"{COLORS['CYAN']}[INFO]    ",
        "WARN": f"{COLORS['YELLOW']}[WARN]    ",
        "ERROR": f"{COLORS['RED']}[ERROR]   ",
        "SUCCESS": f"{COLORS['GREEN']}[SUCCESS] ",
        "PROGRESS": f"{COLORS['BLUE']}[PROGRESS]"
    }
    
    print(f"{level_display.get(level, '[LOG]     ')} {timestamp} │ {message}{COLORS['RESET']}")

def normalize_url(url):
    """Normalize URL (add https:// if missing)"""
    url = url.strip()
    # Remove any existing http:// or https://
    url = re.sub(r'^https?://', '', url)
    # Add https:// prefix
    return f"https://{url}"

def validate_domain(url, timeout):
    """Validate domain format and connectivity"""
    try:
        # Normalize URL
        url = normalize_url(url)
        
        log("INFO", f"Validating connection to {url}...")
        
        # Test connection
        response = requests.head(
            url, 
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True
        )
        
        if response.status_code >= 200 and response.status_code < 400:
            log("SUCCESS", f"Connected to {url} (Status: {response.status_code})")
            return url
        else:
            log("ERROR", f"Cannot connect to domain (Status {response.status_code}): {url}")
            return None
    except RequestException as e:
        log("ERROR", f"Connection failed: {url} - {str(e)}")
        return None

def validate_response_reflection(response_text, payload_value, location_header=None):
    """Enhanced validation of payload reflection in responses focusing on 302"""
    if not payload_value:
        return False, None
    
    reflection_details = {
        'is_reflected': False,
        'location_reflection': False,
        'context': None
    }
    
    # Check location header for reflection
    if location_header:
        if payload_value.lower() in location_header.lower():
            reflection_details['location_reflection'] = True
            reflection_details['context'] = f"Location: {location_header}"
    
    return reflection_details

def compare_responses(baseline, test_response, payload_value, threshold=0.85):
    """
    Enhanced response comparison with similarity scoring
    Returns (is_different, difference_details)
    """
    differences = {
        'status_changed': False,
        'length_changed': False,
        'content_changed': False,
        'headers_changed': False,
        'reflection_found': False,
        'similarity_score': 1.0
    }
    
    # Status code comparison
    status_diff = abs(baseline['status'] - test_response['status'])
    differences['status_changed'] = status_diff >= 100  # Significant status change
    
    # Content length comparison with percentage
    if baseline['length'] > 0:
        length_diff_percent = abs(test_response['length'] - baseline['length']) / baseline['length']
        differences['length_changed'] = length_diff_percent > 0.15  # 15% threshold
    
    # Header comparison
    important_headers = {'server', 'x-powered-by', 'x-cache', 'cache-control', 'location'}
    header_changes = []
    
    for header in important_headers:
        baseline_value = baseline['headers'].get(header)
        test_value = test_response['headers'].get(header)
        
        if baseline_value != test_value:
            header_changes.append({
                'header': header,
                'baseline': baseline_value,
                'test': test_value
            })
    
    differences['headers_changed'] = len(header_changes) > 0
    
    # Check for payload reflection
    is_reflected, reflection_context = validate_response_reflection(
        test_response['content'],
        payload_value,
        baseline['content']
    )
    differences['reflection_found'] = is_reflected
    
    # Calculate content similarity score
    if baseline['content'] and test_response['content']:
        similarity = difflib.SequenceMatcher(
            None,
            baseline['content'][:1000],  # Compare first 1000 chars
            test_response['content'][:1000]
        ).ratio()
        differences['similarity_score'] = similarity
    
    # Determine if responses are significantly different
    is_different = (
        differences['status_changed'] or
        differences['length_changed'] or
        (differences['reflection_found'] and differences['similarity_score'] < threshold) or
        (len(header_changes) >= 2 and differences['similarity_score'] < threshold)
    )
    
    return is_different, differences

def generate_payloads(target, output_file):
    """Generate headers and payloads with improved variety"""
    log("INFO", f"Generating payloads for {target}...")
    
    domain = urlparse(target).netloc
    random_port = random.randint(1024, 65535)
    random_subdomain = ''.join(random.choices(string.ascii_lowercase, k=8))
    
    payloads = {
        "headers": {
            "X-Forwarded-Host": [
                domain,
                "evil.com",
                f"{domain}:{random_port}",
                "localhost",
                "127.0.0.1",
                f"{random_subdomain}.{domain}",
                f"{domain}.evil.com",
                f"attacker-{random.randint(1000,9999)}.com"
            ],
            "X-Original-URL": [
                "/admin",
                "/wp-admin",
                "/.env",
                "/api/internal",
                "/graphql",
                "/actuator",
                "/private",
                "/dashboard",
                f"/{random_subdomain}",
                "/api/v1/admin"
            ],
            "X-HTTP-Host-Override": [
                domain,
                "evil.com",
                f"{random_subdomain}.{domain}",
                f"{domain}:{random_port}"
            ],
            "X-Forwarded-Scheme": [
                "http",
                "https",
                "ws",
                "wss"
            ],
            "X-Forwarded-Proto": [
                "http",
                "https",
                "ws",
                "wss"
            ],
            "X-Forwarded-For": [
                "127.0.0.1",
                "192.168.0.1",
                "10.0.0.1",
                "172.16.0.1",
                "169.254.169.254",  # AWS metadata
                f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
            ],
            "X-Real-IP": [
                "127.0.0.1",
                "localhost",
                "192.168.0.1",
                "169.254.169.254"
            ],
            "X-Custom-IP-Authorization": [
                "127.0.0.1",
                "192.168.0.1",
                "10.0.0.1"
            ],
            "X-Original-Host": [
                domain,
                "evil.com",
                f"{random_subdomain}.{domain}",
                f"{domain}.evil.com"
            ],
            "X-Originating-IP": [
                "127.0.0.1",
                "192.168.0.1",
                "169.254.169.254"
            ],
            "CF-Connecting-IP": [
                "127.0.0.1",
                "192.168.0.1"
            ],
            "X-Cache-Control": [
                "no-cache",
                "no-store",
                "max-age=0",
                "must-revalidate"
            ],
            "X-Rewrite-URL": [
                "/admin",
                "/internal",
                "/api/private",
                f"/{random_subdomain}"
            ],
            "X-Override-URL": [
                "/admin",
                "/internal",
                "/private",
                f"/{random_subdomain}"
            ],
            "X-Client-IP": [
                "127.0.0.1",
                "192.168.0.1",
                "10.0.0.1"
            ],
            "Client-IP": [
                "127.0.0.1",
                "192.168.0.1",
                "10.0.0.1"
            ],
            "True-Client-IP": [
                "127.0.0.1",
                "192.168.0.1",
                "10.0.0.1"
            ]
        },
        "cache_busters": [
            f"cb={int(time.time())}",
            f"nocache={''.join(random.choices(string.hexdigits, k=16))}",
            f"_={int(time.time()*1000000)}",
            f"timestamp={int(time.time())}",
            f"rand={''.join(random.choices(string.ascii_letters + string.digits, k=10))}",
            f"unique={os.urandom(8).hex()}",
            f"t={int(time.time())}-{os.urandom(4).hex()}"
        ]
    }
    
    with open(output_file, 'w') as f:
        json.dump(payloads, f, indent=4)
    
    header_count = sum(len(values) for values in payloads["headers"].values())
    log("SUCCESS", f"Generated {len(payloads['headers'])} header types with {header_count} payload variants")

def discover_urls(target, output_dir, timeout):
    """Discover URLs for the target domain with improved progress tracking"""
    urls_file = os.path.join(output_dir, "discovered_urls.txt")
    filtered_urls_file = os.path.join(output_dir, "filtered_urls.txt")
    
    log("INFO", f"Starting URL discovery for {target}...")
    
    discovered_urls = set()
    target_domain = urlparse(target).netloc
    
    def is_same_domain(url):
        """Check if URL belongs to target domain"""
        try:
            parsed = urlparse(url)
            return parsed.netloc == target_domain or parsed.path.startswith('/')
        except:
            return False
    
    def normalize_path(url):
        """Normalize URL paths"""
        try:
            parsed = urlparse(url)
            path = parsed.path.rstrip('/') or '/'
            return urljoin(target, path)
        except:
            return url
    
    # Common endpoints to check
    common_endpoints = [
        "",
        "api",
        "v1",
        "v2",
        "admin",
        "portal",
        "graphql",
        "wp-json",
        ".well-known",
        "actuator",
        "metrics",
        "health",
        "status",
        "api-docs",
        "swagger",
        "openapi",
        "docs",
        "help",
        "debug",
        "internal",
        "private",
        "public",
        "auth",
        "login",
        "user",
        "admin",
        "dashboard",
        "console",
        "management",
        "monitor",
        "static",
        "assets",
        "images",
        "css",
        "js",
        "lib",
        "vendor",
        "includes",
        "upload",
        "uploads",
        "files",
        "temp",
        "cache"
    ]
    
    # Add common endpoints
    for endpoint in common_endpoints:
        discovered_urls.add(normalize_path(f"{target}/{endpoint}/"))
    
    log("PROGRESS", f"Added {len(common_endpoints)} common endpoints as starting points")
    
    # Perform recursive crawling with depth limit
    def crawl_url(url, depth=0, max_depth=2, pbar=None):
        if depth >= max_depth:
            return
        
        try:
            if pbar:
                # Truncate URL for display
                display_url = url
                if len(display_url) > 30:
                    display_url = f"{display_url[:27]}..."
                pbar.set_description(f"Crawling {display_url}")
            
            response = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True
            )
            
            if response.status_code == 200:
                # Extract URLs from HTML content
                urls = re.findall(r'(?:href|src|action|url)=["\']([^"\']+)["\']', response.text)
                
                # Extract URLs from JavaScript
                js_urls = re.findall(r'(?:"|\'|\`)(\/[^"\'`]+)(?:"|\'|\`)', response.text)
                urls.extend(js_urls)
                
                # Extract from common API formats
                api_paths = re.findall(r'(?:"|\'|\`)(\/api\/[^"\'`]+)(?:"|\'|\`)', response.text)
                urls.extend(api_paths)
                
                new_urls_found = 0
                for found_url in urls:
                    if found_url.startswith('/'):
                        full_url = urljoin(target, found_url)
                    elif found_url.startswith(('http://', 'https://')):
                        full_url = found_url
                    else:
                        full_url = urljoin(url, found_url)
                    
                    if is_same_domain(full_url) and full_url not in discovered_urls:
                        discovered_urls.add(normalize_path(full_url))
                        new_urls_found += 1
                        if len(discovered_urls) < MAX_URLS:
                            if depth < max_depth - 1:  # Only recurse if not at max_depth-1
                                crawl_url(full_url, depth + 1, max_depth, pbar)
                
                if pbar:
                    pbar.update(1)
                    if new_urls_found > 0:
                        pbar.set_postfix(total=len(discovered_urls), new=new_urls_found)
                
        except RequestException:
            if pbar:
                pbar.update(1)
            pass
    
    # Start crawling from the main target
    crawl_total = 100  # Initial estimate
    
    with tqdm(
        total=crawl_total, 
        desc="URL Discovery", 
        unit="url", 
        bar_format=PROGRESS_BAR_FORMAT,
        dynamic_ncols=True
    ) as pbar:
        crawl_url(target, pbar=pbar)
        
        # Adjust the total if we found more or less than expected
        total_discovered = len(discovered_urls)
        pbar.total = min(total_discovered, MAX_URLS)
        pbar.refresh()
    
    # Filter URLs with a clean sub-progress bar
    log("PROGRESS", f"Filtering discovered URLs ({len(discovered_urls)} found)...")
    filtered_urls = set()
    excluded_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.svg', '.ico', '.woff', '.ttf', '.eot'}
    
    with tqdm(
        total=len(discovered_urls), 
        desc="Filtering URLs", 
        unit="url", 
        bar_format=FINAL_PROGRESS_BAR_FORMAT,
        dynamic_ncols=True
    ) as pbar:
        for url in discovered_urls:
            try:
                parsed = urlparse(url)
                ext = os.path.splitext(parsed.path)[1].lower()
                
                if (ext not in excluded_extensions and
                    is_same_domain(url) and
                    len(filtered_urls) < MAX_URLS):
                    filtered_urls.add(url)
                
                pbar.update(1)
                pbar.set_postfix(kept=len(filtered_urls))
            except:
                pbar.update(1)
                continue
    
    # Write filtered URLs to file
    with open(filtered_urls_file, 'w') as f:
        for url in sorted(filtered_urls):
            f.write(f"{url}\n")
    
    log("SUCCESS", f"Discovered {len(filtered_urls)} unique endpoints for {target_domain}")
    return list(filtered_urls)

def validate_with_curl(url, header_name, header_value):
    """Generate curl commands for manual validation"""
    commands = f"""
# Baseline request:
curl -i -s -o /dev/null -w "Status: %{{http_code}}\nLocation: %{{redirect_url}}\n" \\
    -H "User-Agent: Mozilla/5.0" \\
    "{url}?cb=$(date +%s)"

# Test with {header_name}:
curl -i -s -o /dev/null -w "Status: %{{http_code}}\nLocation: %{{redirect_url}}\n" \\
    -H "{header_name}: {header_value}" \\
    -H "User-Agent: Mozilla/5.0" \\
    "{url}?cb=$(date +%s)"

# Verify cached response:
curl -i -s -o /dev/null -w "Status: %{{http_code}}\nLocation: %{{redirect_url}}\n" \\
    -H "User-Agent: Mozilla/5.0" \\
    "{url}?cb=$(date +%s)"
"""
    return commands

def verify_302_poisoning(url, header_name, header_value, timeout=10):
    """Verify 302-based cache poisoning vulnerabilities"""
    results = []
    
    # Generate unique cache busters
    cache_busters = [
        f"verify_{int(time.time())}_{i}_{os.urandom(4).hex()}"
        for i in range(3)
    ]
    
    # First, get baseline response
    try:
        baseline = requests.get(
            f"{url}?cb={cache_busters[0]}", 
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=False
        )
        
        baseline_location = baseline.headers.get('Location', '')
        
        # Only proceed if baseline is not already 302
        if baseline.status_code == 302:
            if header_value.lower() in baseline_location.lower():
                return None, "Baseline already contains payload in redirect"
            
        # Test with multiple cache busters
        for cache_buster in cache_busters[1:]:
            test_url = f"{url}?{cache_buster}"
            
            try:
                response = requests.get(
                    test_url,
                    headers={
                        "User-Agent": USER_AGENT,
                        header_name: header_value
                    },
                    timeout=timeout,
                    allow_redirects=False
                )
                
                if response.status_code == 302:
                    location = response.headers.get('Location', '')
                    reflection = validate_response_reflection(
                        response.text,
                        header_value,
                        location
                    )
                    
                    # Verify the redirection is different and contains our payload
                    if reflection['location_reflection']:
                        results.append({
                            'url': test_url,
                            'status_code': response.status_code,
                            'location': location,
                            'reflection': reflection,
                            'headers': dict(response.headers)
                        })
                
                time.sleep(1)  # Small delay between tests
                
            except requests.RequestException:
                continue
        
        # Validate results
        if len(results) >= 2:  # At least 2 successful tests
            # Check consistency of results
            locations = [r['location'] for r in results]
            if len(set(locations)) == 1:  # All locations are identical
                return results[0], None
        
        return None, "Inconsistent or insufficient 302 responses"
        
    except requests.RequestException as e:
        return None, f"Error during verification: {str(e)}"

def test_cache_poisoning(url, payloads_file, output_file, mode="standard", timeout=10, pbar=None):
    """Enhanced cache poisoning test with cleaner progress display"""
    try:
        with open(payloads_file, 'r') as f:
            payloads = json.load(f)
        
        total_headers = sum(len(values) for header, values in payloads["headers"].items())
        tested_headers = 0
        
        for header_name, header_values in payloads["headers"].items():
            for header_value in header_values:
                if pbar:
                    tested_headers += 1
                    
                    # Truncate values for display
                    h_display = header_name
                    v_display = header_value
                    
                    if len(h_display) > 10:
                        h_display = f"{h_display[:8]}..."
                    
                    if len(v_display) > 10:
                        v_display = f"{v_display[:8]}..."
                    
                    # Format the progress description
                    progress_percent = (tested_headers / total_headers) * 100
                    pbar.set_description(f"Testing {h_display}:{v_display}")
                    
                    # Format URL for postfix
                    url_display = url
                    if len(url_display) > 20:
                        url_display = f"...{url_display[-17:]}"
                    
                    pbar.set_postfix(progress=f"{progress_percent:.1f}%", url=url_display)
                    pbar.update(1)
                
                result, error = verify_302_poisoning(url, header_name, header_value, timeout)
                
                if result:
                    vulnerability_data = {
                        'url': url,
                        'header': f"{header_name}: {header_value}",
                        'status_code': result['status_code'],
                        'location': result['location'],
                        'reflection_details': result['reflection'],
                        'verification': {
                            'status': 'verified',
                            'type': '302_redirect'
                        }
                    }
                    
                    with open(output_file, 'a') as f:
                        f.write(f"{json.dumps(vulnerability_data)}\n")
                    
                    log("SUCCESS", f"Found 302 cache poisoning: {header_name}: {header_value}")
                    log("INFO", f"→ Redirects to: {result['location'][:60]}...")
                
                time.sleep(0.5)  # Rate limiting
                
    except Exception as e:
        log("ERROR", f"Error testing {url}: {str(e)}")
        if pbar:
            pbar.update(pbar.total - pbar.n)  # Complete the progress bar on error

def scan_target(target, threads, delay, mode, base_output_dir, verbose, timeout):
    """Scan a single target for cache poisoning vulnerabilities with clean progress tracking"""
    # Normalize and validate target
    valid_target = validate_domain(target, timeout)
    if not valid_target:
        log("ERROR", f"Cannot proceed with {target} - validation failed")
        return False
    
    target = valid_target
    
    # Create target-specific output directory
    domain = urlparse(target).netloc
    target_output_dir = os.path.join(base_output_dir, domain)
    os.makedirs(target_output_dir, exist_ok=True)
    
    # Header with target information
    header_line = f" SCANNING TARGET: {domain} "
    padding = "═" * ((TERM_WIDTH - len(header_line)) // 2)
    log("INFO", f"{padding}{header_line}{padding}")
    
    # Generate payloads
    payloads_file = os.path.join(target_output_dir, "payloads.json")
    generate_payloads(target, payloads_file)
    
    # Discover URLs
    urls = discover_urls(target, target_output_dir, timeout)
    
    if not urls:
        log("WARN", f"No valid URLs found for target: {target}")
        return False
    
    # Process URLs in parallel
    results_file = os.path.join(target_output_dir, "results.txt")
    
    # Create/clear results file
    open(results_file, 'w').close()
    
    # Calculate total work items for progress tracking
    with open(payloads_file, 'r') as f:
        payloads = json.load(f)
    
    headers_per_url = sum(len(values) for header, values in payloads["headers"].items())
    total_tests = len(urls) * headers_per_url
    
    log("PROGRESS", f"Testing {len(urls)} URLs with {headers_per_url} header variations = {total_tests} tests")
    
    # Initialize thread pool for parallel processing
    log("INFO", f"Using {threads} parallel threads for testing")
    
    # Create single, cleaner progress bar for all tests
    with tqdm(
        total=total_tests, 
        desc="Cache Testing", 
        unit="test",
        bar_format=PROGRESS_BAR_FORMAT,
        dynamic_ncols=True
    ) as main_pbar:
        # Track URLs being processed for display
        active_urls = set()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_url = {}
            
            # Submit all work in batches
            for i, url in enumerate(urls):
                # Display periodic progress updates for URL submission
                if i % max(1, min(len(urls) // 10, 50)) == 0:
                    progress_percentage = (i / len(urls)) * 100
                    url_display = url
                    if len(url_display) > 40:
                        url_display = f"{url_display[:37]}..."
                    log("PROGRESS", f"Queuing batch {i//50 + 1}: {progress_percentage:.1f}% complete")
                
                future = executor.submit(
                    test_cache_poisoning, 
                    url, 
                    payloads_file, 
                    results_file, 
                    mode,
                    timeout,
                    main_pbar  # Pass the progress bar
                )
                future_to_url[future] = url
                active_urls.add(url)
                
                # Add small delay between URL submissions to prevent overloading
                if i % 10 == 0:
                    time.sleep(delay)
            
            # Process results as they complete
            completed = 0
            total_urls = len(urls)
            
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                completed += 1
                active_urls.remove(url)
                
                try:
                    future.result()  # Get any exceptions
                    
                    # Report progress at reasonable intervals
                    if verbose or completed % max(1, min(total_urls // 5, 10)) == 0:
                        completion_percentage = (completed / total_urls) * 100
                        log("PROGRESS", f"Completed {completed}/{total_urls} URLs ({completion_percentage:.1f}%)")
                except Exception as e:
                    log("ERROR", f"Error in URL {url}: {str(e)}")
    
    # Check for any vulnerabilities found
    if os.path.exists(results_file) and os.path.getsize(results_file) > 0:
        with open(results_file, 'r') as f:
            vulnerability_count = sum(1 for _ in f)
        log("SUCCESS", f"Found {vulnerability_count} cache poisoning vulnerabilities in {target}")
    else:
        log("INFO", f"No cache poisoning vulnerabilities found in {target}")
    
    # Final separator line
    log("SUCCESS", f"{'═' * TERM_WIDTH}")
    return True

def generate_report(output_dir, start_time, end_time):
    """Generate enhanced HTML report with findings and progress tracking"""
    report_file = os.path.join(output_dir, "report.html")
    duration = end_time - start_time
    
    log("PROGRESS", "Generating final scan report...")
    
    # Combine all results
    all_results_file = os.path.join(output_dir, "all_results.txt")
    
    # Find and combine all result files with progress bar
    result_files = []
    for root, _, files in os.walk(output_dir):
        for file in files:
            if file == "results.txt":
                result_files.append(os.path.join(root, file))
    
    with tqdm(
        total=len(result_files), 
        desc="Collecting Results", 
        unit="file",
        bar_format=SUB_PROGRESS_BAR_FORMAT,
        dynamic_ncols=True
    ) as pbar:
        with open(all_results_file, 'w') as outfile:
            for file_path in result_files:
                with open(file_path, 'r') as infile:
                    content = infile.read()
                    if content:
                        outfile.write(content)
                pbar.update(1)
    
    vulnerabilities = []
    if os.path.exists(all_results_file) and os.path.getsize(all_results_file) > 0:
        with open(all_results_file, 'r') as f:
            for line in f:
                try:
                    vuln_data = json.loads(line.strip())
                    vulnerabilities.append(vuln_data)
                except json.JSONDecodeError:
                    continue
    
    # Generate HTML report with clean progress tracking
    with tqdm(
        total=5, 
        desc="Creating Report", 
        unit="section",
        bar_format=FINAL_PROGRESS_BAR_FORMAT,
        dynamic_ncols=True
    ) as pbar:
        with open(report_file, 'w') as f:
            # Write report header
            f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Cache Poisoning Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; line-height: 1.6; color: #333; background-color: #f8f9fa; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .header p {{ margin: 5px 0 0; opacity: 0.9; }}
        .vulnerability {{ margin: 25px 0; padding: 20px; border-radius: 8px; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
        .vulnerability h3 {{ color: #e74c3c; margin-top: 0; border-bottom: 2px solid #f0f0f0; padding-bottom: 10px; }}
        .summary {{ background: linear-gradient(to right, #00b09b, #96c93d); padding: 25px; border-radius: 8px; margin: 30px 0; color: white; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .summary h2 {{ margin-top: 0; }}
        .details {{ margin: 15px 0; padding: 15px; background: #f8f9fa; border-radius: 6px; }}
        .changes {{ margin: 15px 0; padding: 15px; background: #fff3cd; border-radius: 6px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
        th, td {{ border: 1px solid #f0f0f0; padding: 12px 15px; text-align: left; }}
        th {{ background-color: #f8f9fa; font-weight: 600; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .footer {{ margin-top: 50px; text-align: center; font-size: 0.9em; color: #777; padding: 20px; }}
        .stats {{ display: flex; justify-content: space-around; margin: 25px 0; flex-wrap: wrap; }}
        .stat-box {{ padding: 20px; background: rgba(255,255,255,0.2); border-radius: 8px; text-align: center; margin: 10px; flex: 1; min-width: 200px; }}
        .stat-box h3 {{ margin: 0 0 10px 0; font-size: 16px; }}
        .stat-box p {{ margin: 0; font-size: 24px; font-weight: bold; }}
        .reflection {{ background: #ffe6e6; padding: 15px; margin: 15px 0; border-left: 4px solid #ff4444; border-radius: 4px; }}
        code, pre {{ background: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 6px; overflow: auto; font-family: 'Courier New', monospace; font-size: 14px; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-right: 5px; }}
        .badge-danger {{ background: #e74c3c; color: white; }}
        .badge-warning {{ background: #f39c12; color: white; }}
        .badge-success {{ background: #2ecc71; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Enhanced Cache Poisoning Scan Report</h1>
            <p><strong>Scan Duration:</strong> {duration:.2f} seconds</p>
            <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Scanner Version:</strong> {VERSION}</p>
        </div>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="stats">
                <div class="stat-box">
                    <h3>Total Vulnerabilities</h3>
                    <p>{len(vulnerabilities)}</p>
                </div>
                <div class="stat-box">
                    <h3>Unique Domains</h3>
                    <p>{len(set(urlparse(v['url']).netloc for v in vulnerabilities))}</p>
                </div>
                <div class="stat-box">
                    <h3>Verification Rate</h3>
                    <p>100%</p>
                </div>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
""")
            pbar.update(1)
            
            if vulnerabilities:
                # Add vulnerability table
                f.write("""
        <table>
            <tr>
                <th>Target URL</th>
                <th>Vulnerable Header</th>
                <th>Status Code</th>
                <th>Vulnerability Type</th>
            </tr>
""")
                
                for vuln in vulnerabilities:
                    f.write(f"""
            <tr>
                <td>{vuln['url']}</td>
                <td>{vuln['header']}</td>
                <td><span class="badge badge-warning">{vuln['status_code']}</span></td>
                <td><span class="badge badge-danger">{vuln['verification']['type']}</span></td>
            </tr>""")
                
                f.write("""
        </table>
        
        <h2>Detailed Vulnerability Analysis</h2>
""")
                pbar.update(1)
                
                # Write vulnerability details in batches for better progress tracking
                batch_size = max(1, len(vulnerabilities) // 3)
                for i in range(0, len(vulnerabilities), batch_size):
                    batch = vulnerabilities[i:i+batch_size]
                    
                    for j, vuln in enumerate(batch, i+1):
                        f.write(f"""
        <div class="vulnerability">
            <h3>Vulnerability #{j}</h3>
            
            <div class="details">
                <p><strong>Target URL:</strong> {vuln['url']}</p>
                <p><strong>Vulnerable Header:</strong> {vuln['header']}</p>
                <p><strong>Status Code:</strong> <span class="badge badge-warning">{vuln['status_code']}</span></p>
                
                <h4>Vulnerability Details:</h4>
                <ul>
                    <li>Type: <span class="badge badge-danger">{vuln['verification']['type']}</span></li>
                    <li>Redirects to: {vuln['location']}</li>
                    <li>Verification Status: <span class="badge badge-success">{vuln['verification']['status']}</span></li>
                </ul>
""")
                        
                        # Add reflection details if available
                        if vuln.get('reflection_details') and vuln['reflection_details'].get('location_reflection'):
                            f.write("""
                    <div class="reflection">
                        <h4>Payload Reflection Details:</h4>
                        <p>The injected payload was found reflected in the Location header, indicating a cache poisoning vulnerability.</p>
                    </div>""")
                        
                        # Add curl commands for manual verification
                        header_name, header_value = vuln['header'].split(': ', 1)
                        curl_commands = validate_with_curl(vuln['url'], header_name, header_value)
                        
                        f.write(f"""
                    <h4>Validation Commands:</h4>
                    <pre>{curl_commands}</pre>
                </div>
            </div>""")
                        
                    pbar.update(1)
                    
            else:
                f.write("<p>No vulnerabilities were found during the scan.</p>")
                pbar.update(2)  # Skip the vulnerability processing steps
                
            # Add recommendations section
            f.write("""
        <div class="summary" style="background: linear-gradient(to right, #2980b9, #6dd5fa);">
            <h2>Recommendations</h2>
            <ul>
                <li>Review and validate all identified cache poisoning vectors</li>
                <li>Implement proper cache key generation that includes all relevant request components</li>
                <li>Configure strict caching policies and header validation</li>
                <li>Consider implementing cache poisoning countermeasures such as Vary headers</li>
                <li>Regular security testing and monitoring of caching behavior</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>Generated by Enhanced Cache Poisoning Scanner v{VERSION}</p>
            <p>Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>""")
            pbar.update(1)
    
    log("SUCCESS", f"Report generated: {report_file}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description=f"Enhanced Cache Poisoning Scanner v{VERSION}")
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', help='Target domain (e.g., example.com or https://example.com)')
    target_group.add_argument('-f', '--file', help='File containing list of domains (one per line)')
    
    parser.add_argument('-j', '--threads', type=int, default=DEFAULT_THREADS, 
                        help=f'Number of parallel threads (default: {DEFAULT_THREADS})')
    parser.add_argument('-d', '--delay', type=float, default=DEFAULT_DELAY,
                        help=f'Delay between requests in seconds (default: {DEFAULT_DELAY})')
    parser.add_argument('-m', '--mode', choices=['standard', 'aggressive', 'stealth'], 
                        default='standard', help='Scanning mode (standard, aggressive, stealth)')
    parser.add_argument('-o', '--output', help='Output directory (default: cache_scan_[timestamp])')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})')
    
    args = parser.parse_args()
    
    show_banner()
    
    # Set up output directory
    if not args.output:
        args.output = f"cache_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    os.makedirs(args.output, exist_ok=True)
    
    start_time = time.time()
    
    try:
        # Process targets
        if args.target:
            # Single target mode
            target_start_time = time.time()
            success = scan_target(args.target, args.threads, args.delay, args.mode, 
                                args.output, args.verbose, args.timeout)
            target_duration = time.time() - target_start_time
            
            if success:
                log("SUCCESS", f"Completed scan of {args.target} in {target_duration:.2f} seconds")
            else:
                log("WARN", f"Scan of {args.target} did not complete successfully")
                
        else:
            # Multiple targets mode
            if not os.path.isfile(args.file):
                log("ERROR", f"Input file not found: {args.file}")
                return 1
            
            with open(args.file, 'r') as f:
                domains = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            
            total_targets = len(domains)
            log("INFO", f"Starting scan of {total_targets} targets")
            
            # Create a progress bar for multiple targets
            with tqdm(
                total=total_targets, 
                desc="Target Progress", 
                unit="domain", 
                bar_format=PROGRESS_BAR_FORMAT,
                dynamic_ncols=True
            ) as target_pbar:
                for i, domain in enumerate(domains, 1):
                    # Clean display of domain
                    if len(domain) > 30:
                        display_domain = f"{domain[:27]}..."
                    else:
                        display_domain = domain
                        
                    target_pbar.set_description(f"Domain: {display_domain}")
                    
                    log("INFO", f"Starting target {i}/{total_targets}: {domain}")
                    target_start_time = time.time()
                    success = scan_target(domain, args.threads, args.delay, args.mode, 
                                        args.output, args.verbose, args.timeout)
                    target_duration = time.time() - target_start_time
                    
                    if success:
                        status = "✓"
                        log("SUCCESS", f"Completed scan of {domain} in {target_duration:.2f} seconds")
                    else:
                        status = "✗"
                        log("WARN", f"Scan of {domain} did not complete successfully")
                    
                    # Update progress
                    target_pbar.update(1)
                    progress_pct = ((i)/total_targets)*100
                    target_pbar.set_postfix(status=status, progress=f"{progress_pct:.1f}%")
        
        # Generate final report
        end_time = time.time()
        generate_report(args.output, start_time, end_time)
        
        # Show summary
        all_results_file = os.path.join(args.output, "all_results.txt")
        if os.path.exists(all_results_file) and os.path.getsize(all_results_file) > 0:
            with open(all_results_file, 'r') as f:
                count = sum(1 for _ in f)
            log("SUCCESS", f"Found {count} verified vulnerabilities!")
            log("INFO", f"Check {args.output}/report.html for detailed results")
        else:
            log("INFO", "No vulnerabilities found")
        
        total_duration = end_time - start_time
        log("SUCCESS", f"Scan completed in {total_duration:.2f} seconds")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n")  # Add a newline for cleaner output after progress bar
        log("WARN", "Scan interrupted by user")
        return 1
    except Exception as e:
        print("\n")  # Add a newline for cleaner output after progress bar
        log("ERROR", f"Unexpected error: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())