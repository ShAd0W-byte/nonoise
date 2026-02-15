# visitor.py - URL visiting and WordPress enumeration with browser-like behavior
import requests
import asyncio
import aiohttp
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import random

# =========================
# CONFIG
# =========================

# URL Visiting Config (will be overridden by user input)
URL_WORKERS = 70
TIMEOUT = 10

# WordPress Config (fixed - does NOT use user threads)
WP_CONCURRENCY = 30
WP_TIMEOUT = 10
WP_ALLOWED_STATUS = {200, 301, 302, 401, 403, 405}

# =========================
# BROWSER EMULATION
# =========================

USER_AGENTS = [
    # Chrome on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    # Chrome on macOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    # Firefox on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    # Firefox on macOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
    # Safari on macOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    # Edge on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    # Chrome on Linux
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
]

def get_browser_headers(url):
    """Generate realistic browser headers"""
    parsed = urlparse(url)
    domain = parsed.netloc
    
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
    }
    
    # Add referer for non-root paths
    if parsed.path and parsed.path != '/':
        headers['Referer'] = f"{parsed.scheme}://{domain}/"
    
    return headers

# =========================
# STATUS CODE TABLES
# =========================

DROP_STATUS = set(range(100, 200)) | {300, 305, 306, 404, 204}

ALLOW_STATUS = {
    200, 201, 202, 301, 302, 303, 304,
    401, 403, 405, 409, 422, 429,
    500, 502, 503, 504
}

# =========================
# REQUEST HANDLER
# =========================

def fetch_status_and_headers(url):
    """Fetch URL status code and headers with browser-like behavior"""
    headers = get_browser_headers(url)
    
    # Create session with browser-like settings
    session = requests.Session()
    session.headers.update(headers)
    
    try:
        # Try HEAD request first (faster)
        r = session.head(
            url,
            allow_redirects=False,
            timeout=TIMEOUT,
            verify=True  # Verify SSL certificates like browsers do
        )
        return url, r.status_code, r.headers
    except requests.exceptions.SSLError:
        # Retry with SSL verification disabled for broken certificates
        try:
            r = session.head(url, allow_redirects=False, timeout=TIMEOUT, verify=False)
            return url, r.status_code, r.headers
        except requests.RequestException:
            pass
    except requests.RequestException:
        pass
    
    # If HEAD fails, try GET request
    try:
        r = session.get(
            url,
            allow_redirects=False,
            timeout=TIMEOUT,
            verify=True,
            stream=True  # Don't download full content
        )
        r.close()  # Close connection immediately
        return url, r.status_code, r.headers
    except requests.exceptions.SSLError:
        try:
            r = session.get(url, allow_redirects=False, timeout=TIMEOUT, verify=False, stream=True)
            r.close()
            return url, r.status_code, r.headers
        except requests.RequestException:
            return url, None, None
    except requests.RequestException:
        return url, None, None

# =========================
# 301 FILTER LOGIC
# =========================

def should_drop_301(url, headers):
    """Determine if 301 redirect should be dropped"""
    parsed = urlparse(url)
    location = headers.get("Location", "")

    # HTTP → HTTPS without params
    if parsed.scheme == "http" and not parsed.query:
        return True

    # www → non-www canonical
    if "www." in parsed.netloc:
        target = parsed.netloc.replace("www.", "")
        if location.startswith(("http://" + target, "https://" + target)):
            return True

    # Trailing slash normalization
    if location.rstrip("/") == url.rstrip("/"):
        return True

    return False

# =========================
# URL PROCESSOR
# =========================

def process_single_url(url):
    """Process a single URL and determine if it should be kept"""
    url, status, headers = fetch_status_and_headers(url)

    if status is None:
        return None

    if status in DROP_STATUS:
        return None

    if status == 200:
        return (url, status)

    if status == 301:
        if headers and should_drop_301(url, headers):
            return None
        return (url, status)

    if status in ALLOW_STATUS:
        return (url, status)

    # Unknown status → keep
    return (url, status)

# =========================
# FILE PROCESSOR
# =========================

def process_file(file_path: Path, output_dir: Path, workers: int):
    """Process a single file's URLs"""
    output_file = output_dir / f"{file_path.stem}_visited.txt"
    results = []

    with file_path.open(errors="ignore") as f:
        urls = [line.strip() for line in f if line.strip()]

    # Process URLs concurrently with user-specified workers
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(process_single_url, url) for url in urls]

        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)

    # Write results
    with output_file.open("w") as out:
        for url, status in results:
            out.write(f"{url} {status}\n")

    return len(results)

# =========================
# WORDPRESS SCANNER
# =========================

async def fetch_wp_url(session, url, semaphore, results):
    """Fetch a single WordPress URL asynchronously with browser headers"""
    async with semaphore:
        try:
            headers = {
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            async with session.get(
                url,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=WP_TIMEOUT),
                headers=headers,
                ssl=False  # Handle SSL errors gracefully
            ) as resp:
                if resp.status in WP_ALLOWED_STATUS:
                    results.append(f"{url} {resp.status}")
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass  # silently drop

async def scan_wordpress_domain(domain, paths):
    """Scan a single domain for WordPress paths"""
    base_url = f"https://{domain}"
    semaphore = asyncio.Semaphore(WP_CONCURRENCY)
    results = []

    # Create session with browser-like settings
    connector = aiohttp.TCPConnector(limit=WP_CONCURRENCY, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for path in paths:
            full_url = base_url + path
            tasks.append(fetch_wp_url(session, full_url, semaphore, results))

        await asyncio.gather(*tasks)

    return results

async def run_wordpress_scanner(domains, wordlist_path, output_file):
    """Run WordPress scanner for all domains"""
    
    if not Path(wordlist_path).exists():
        return
    
    paths = [line.strip() for line in Path(wordlist_path).read_text().splitlines() if line.strip()]

    all_results = []

    for domain in domains:
        domain_results = await scan_wordpress_domain(domain, paths)
        all_results.extend(domain_results)

    Path(output_file).write_text("\n".join(all_results))

# =========================
# MAIN VISITOR FUNCTION
# =========================

def visit_urls(input_dir, wordpress_enabled=False, wordpress_domains=None, config=None):
    """
    Main visitor function called by engine
    
    Args:
        input_dir: Path - Directory containing URL files from collector
        wordpress_enabled: bool - Whether to run WordPress scanner
        wordpress_domains: list[str] - List of domains for WordPress scanning (root domains only)
        config: dict - Configuration (threads for URL visiting, etc.)
    
    Returns:
        Path - Output directory with visited URLs
    """
    
    if config is None:
        config = {}
    
    # Get user-specified threads (only for URL visiting, NOT WordPress)
    url_workers = config.get("threads", URL_WORKERS)
    
    # Create output directory
    output_dir = Path("nonoise_output")
    output_dir.mkdir(exist_ok=True)
    
    # ===================================
    # PART 1: Visit URLs from collector
    # ===================================
    
    input_files = list(Path(input_dir).glob("*.txt"))
    
    if input_files:
        # Determine number of file workers
        file_workers = min(len(input_files), 10)  # Max 10 files concurrently
        
        with ThreadPoolExecutor(max_workers=file_workers) as executor:
            futures = [executor.submit(process_file, f, output_dir, url_workers) for f in input_files]
            
            total_kept = 0
            for future in as_completed(futures):
                total_kept += future.result()
    
    # ===================================
    # PART 2: WordPress Scanner (Optional)
    # ===================================
    
    if wordpress_enabled:
        if wordpress_domains:
            # WordPress wordlist path (fixed name in same directory)
            wp_wordlist = "wordpress-top500.txt"
            wp_output = "wordpress_results.txt"
            
            # Run async WordPress scanner (uses fixed WP_CONCURRENCY, not user threads)
            asyncio.run(run_wordpress_scanner(wordpress_domains, wp_wordlist, wp_output))
    
    return output_dir


if __name__ == "__main__":
    # Test mode
    test_input_dir = Path("trash_files")
    test_output = visit_urls(
        input_dir=test_input_dir,
        wordpress_enabled=False,
        wordpress_domains=["example.com"],
        config={"threads": 70}
    )
