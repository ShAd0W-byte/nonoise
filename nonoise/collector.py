import requests
import json
import os
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from urllib.parse import urlparse, parse_qs, urlunparse
import time
import re
import random
import threading
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from queue import Queue
from typing import Dict, List, Set, Tuple, Optional


# CONFIGURATION


# Wayback Machine Config
WAYBACK_TIMEOUT = 30
WAYBACK_RETRIES = 3

# CommonCrawl Config
COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"
BASE_INDEX_URL = "https://index.commoncrawl.org"
CC_TIMEOUT = (15, 15)
INDEX_RETRIES = 2
MAX_INDEX_WORKERS_CAP = 15
CC_LATEST_INDEXES_COUNT = 1  # Only use the latest 1 index

# AlienVault Config
ALIENVAULT_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/domain"
ALIENVAULT_TIMEOUT = (15, 15)
ALIENVAULT_RETRIES = 3

# Concurrency Config
MAX_DOMAIN_WORKERS = 20
MAX_FILTER_WORKERS = 10

# URL Generation Config
CLOUD_PATTERNS = [
    # AWS S3
    "https://{b}.s3.amazonaws.com",
    "https://{b}.s3-us-east-1.amazonaws.com",
    "https://{b}.s3.us-east-1.amazonaws.com",
    "https://{b}-prod.s3.amazonaws.com",
    "https://{b}-dev.s3.amazonaws.com",
    "https://{b}-staging.s3.amazonaws.com",
    "https://{b}-backup.s3.amazonaws.com",
    "https://{b}-assets.s3.amazonaws.com",
    "https://s3.amazonaws.com/{b}",
    "https://{b}-static.s3.amazonaws.com",
    "https://{b}-media.s3.amazonaws.com",
    "https://{b}-uploads.s3.amazonaws.com",
    # Azure Blob Storage
    "https://{b}.blob.core.windows.net",
    "https://{b}prod.blob.core.windows.net",
    "https://{b}storage.blob.core.windows.net",
    # DigitalOcean Spaces
    "https://{b}.nyc3.digitaloceanspaces.com",
    "https://{b}.sfo2.digitaloceanspaces.com",
    "https://{b}.ams3.digitaloceanspaces.com",
    # Cloudflare R2
    "https://{b}.r2.cloudflarestorage.com",
]

# Filtering Config
EXTENSION_FILTER = re.compile(
    r"\.(css|scss|less|map|js|mjs|cjs|jsx|tsx|"
    r"jpg|jpeg|png|gif|svg|webp|bmp|ico|tif|tiff|"
    r"mp4|flv|ogv|webm|mov|avi|mkv|"
    r"mp3|m4a|m4p|wav|ogg|aac|"
    r"woff2?|ttf|otf|eot|sfnt|"
    r"pdf|docx?|xlsx?|csv|rtf|"
    r"gzip|gz|rar|7z|"
    r"exe|msi|apk|bin|deb|rpm|"
    r"swf|htc|json)$",
    re.IGNORECASE
)

FRAMEWORK_PATHS = re.compile(
    r"/(assets|static|dist|build|bundle|vendor|vendors|node_modules|"
    r"themes?|css|js|img|image|images|media|audio|video|fonts?|"
    r"captcha|jquery|bootstrap|slick|owl|swiper|lightbox|magnific|"
    r"_astro|_next/static|nuxt|vite|webpack)/",
    re.IGNORECASE
)

CMS_PATHS = re.compile(
    r"/(blog|blogs|news|nieuws|article|articles|artikel|artikelen|"
    r"post|posts|story|stories|author|authors|tag|tags|category|"
    r"categories|topics?|archive|archives|feed|rss|comment|comments|"
    r"comment-page-|amp)/",
    re.IGNORECASE
)

PAGINATION = re.compile(
    r"(/page/\d+|/p/\d+|/pages/\d+|\?.*(page|paged|offset|limit|start|rows|size|from|to|sort|order)=|"
    r"/(19|20)\d{2}/|/year/|/month/|/day/)",
    re.IGNORECASE
)

TRACKING_PARAMS = {
    "utm_source","utm_medium","utm_campaign","utm_term","utm_content",
    "gclid","fbclid","msclkid","yclid","mc_cid","mc_eid",
    "ref","referrer","source","campaign","medium",
    "_ga","_gid","_gat","sessionid","jsessionid","phpsessid",
    "sid","sso","tracking","trackid"
}

STRUCTURAL_NOISE = re.compile(
    r"/\d{2,}|/[0-9a-f]{16,}|/[0-9a-f\-]{36}|/[A-Za-z0-9\-_]{20,}|/\d{10,}"
)

LEGAL_PATHS = re.compile(
    r"/(privacy|terms|conditions|about|contact|help|faq|support|legal|"
    r"press|press-release|press-releases|careers|jobs|cookie|"
    r"newsletter|subscribe|unsubscribe)",
    re.IGNORECASE
)

QUERY_FILE_EXT = re.compile(r"\.(jpg|png|pdf|zip|docx?|xlsx?)$", re.IGNORECASE)
LANG_PATH = re.compile(r"^/(en|en-us|fr|de|es|it|nl|pt|ru|zh|ja)/", re.IGNORECASE)

# Stage 2 Filter Config
QUEUE_LIMIT = 3
SEPARATORS = ['/', '?', '&', '=', '#', '$']


# BROWSER SIMULATION


USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Chrome on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Firefox on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Safari on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
]

def get_random_user_agent() -> str:
    """Get a random user agent string"""
    return random.choice(USER_AGENTS)


def get_browser_headers(referer: Optional[str] = None) -> Dict[str, str]:
    """Generate browser-like headers with random user agent"""
    headers = {
        "User-Agent": get_random_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
        "Sec-Ch-Ua": '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
    }
    
    if referer:
        headers["Referer"] = referer
        headers["Sec-Fetch-Site"] = "same-origin"
    
    return headers


def get_api_headers() -> Dict[str, str]:
    """Generate headers for API requests"""
    return {
        "User-Agent": get_random_user_agent(),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "DNT": "1",
    }


class SessionManager:
    """Thread-safe session manager with connection pooling"""
    
    _local = threading.local()
    
    @classmethod
    def get_session(cls) -> requests.Session:
        """Get or create a thread-local session"""
        if not hasattr(cls._local, 'session'):
            session = requests.Session()
            
            # Configure retry strategy
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS"],
                raise_on_status=False
            )
            
            # Configure connection adapter with pooling
            adapter = HTTPAdapter(
                max_retries=retry_strategy,
                pool_connections=50,
                pool_maxsize=50,
                pool_block=False
            )
            
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            cls._local.session = session
        
        return cls._local.session


def request_with_retry(url: str, timeout: tuple = (10, 30), 
                       max_retries: int = 3, stream: bool = False,
                       headers: Optional[Dict] = None,
                       reduced_delay: bool = False) -> Optional[requests.Response]:
    """Make a request with retry logic and exponential backoff"""
    session = SessionManager.get_session()
    
    if headers is None:
        headers = get_browser_headers()
    
    for attempt in range(max_retries):
        try:
            # Add small random delay to avoid rate limiting
            if attempt > 0:
                if reduced_delay:
                    delay = 0.5 + random.uniform(0, 0.3)
                else:
                    delay = (2 ** attempt) + random.uniform(0, 1)
                time.sleep(delay)
            
            response = session.get(
                url, 
                headers=headers, 
                timeout=timeout, 
                stream=stream,
                allow_redirects=True
            )
            
            # Check for rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 5))
                time.sleep(retry_after)
                continue
            
            return response
            
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                continue
        except requests.exceptions.ConnectionError:
            if attempt < max_retries - 1:
                if reduced_delay:
                    time.sleep(0.5)
                else:
                    time.sleep(2 ** attempt)
                continue
        except requests.exceptions.RequestException:
            if attempt < max_retries - 1:
                continue
    
    return None



# DIRECTORY STRUCTURE


BASE_TEMP_DIR = Path("temp_collection")
WAYBACK_DIR = BASE_TEMP_DIR / "wayback"
CC_DIR = BASE_TEMP_DIR / "commoncrawl"
CC_TEMP_DIR = BASE_TEMP_DIR / "cc_temp"
ALIENVAULT_DIR = BASE_TEMP_DIR / "alienvault"
GENERATED_DIR = BASE_TEMP_DIR / "generated"
COMBINED_DIR = BASE_TEMP_DIR / "combined"
FILTERED1_DIR = BASE_TEMP_DIR / "filtered_stage1"
FILTERED2_DIR = Path("trash_files")  # Final output directory

# Thread-safe print lock
print_lock = threading.Lock()

def safe_print(message: str):
    """Thread-safe printing"""
    with print_lock:
        print(message)
        sys.stdout.flush()


# STAGE 1: WAYBACK MACHINE


def fetch_wayback(domain: str) -> Tuple[str, bool, int]:
    """Fetch URLs from Wayback Machine for a domain"""
    output_file = WAYBACK_DIR / f"{domain}.txt"
    
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url={domain}/*"
        f"&collapse=urlkey"
        f"&fl=original,mimetype,statuscode"
        f"&output=text"
    )
    
    headers = get_browser_headers(referer="https://web.archive.org/")
    
    for attempt in range(WAYBACK_RETRIES):
        try:
            if attempt > 0:
                time.sleep(2 ** attempt + random.uniform(0, 1))
            
            response = request_with_retry(
                url, 
                timeout=(15, WAYBACK_TIMEOUT),
                max_retries=1,
                headers=headers
            )
            
            if response is None:
                continue
                
            if response.status_code == 200:
                output_file.write_text(response.text)
                line_count = len(response.text.strip().split('\n')) if response.text.strip() else 0
                return domain, True, line_count
            elif response.status_code == 429:
                time.sleep(5)
                continue
                
        except Exception:
            if attempt < WAYBACK_RETRIES - 1:
                continue
    
    # Write empty file on failure
    output_file.write_text("")
    return domain, False, 0


# STAGE 2: COMMONCRAWL


def fetch_index_ids() -> List[str]:
    """Fetch latest CommonCrawl index IDs (only the most recent ones)"""
    headers = get_api_headers()
    
    response = request_with_retry(
        COLLINFO_URL, 
        timeout=CC_TIMEOUT,
        headers=headers
    )
    
    if response is None or response.status_code != 200:
        raise Exception("Failed to fetch CommonCrawl index list")
    
    data = response.json()
    all_indexes = sorted([item["id"] for item in data if "id" in item], reverse=True)
    
    # Return only the latest N indexes
    return all_indexes[:CC_LATEST_INDEXES_COUNT]


def fetch_urls_for_index(index_id: str, domain: str, temp_dir: Path) -> Optional[Path]:
    """Fetch URLs from a single CommonCrawl index"""
    temp_file = temp_dir / f"{index_id}.txt"
    
    url = (
        f"{BASE_INDEX_URL}/{index_id}-index"
        f"?url={domain}/*&output=json"
    )
    
    headers = get_api_headers()
    
    for attempt in range(INDEX_RETRIES):
        try:
            if attempt > 0:
                time.sleep(0.5 + random.uniform(0, 0.3))
            
            response = request_with_retry(
                url,
                timeout=CC_TIMEOUT,
                stream=True,
                max_retries=1,
                headers=headers,
                reduced_delay=True
            )
            
            if response is None:
                continue
                
            if response.status_code != 200:
                if response.status_code == 429:
                    time.sleep(2)
                continue
            
            with temp_file.open("w") as f:
                for line in response.iter_lines():
                    if not line:
                        continue
                    try:
                        record = json.loads(line.decode(errors="ignore"))
                        if "url" in record:
                            f.write(record["url"] + "\n")
                    except json.JSONDecodeError:
                        continue
            
            return temp_file
            
        except Exception:
            if attempt < INDEX_RETRIES - 1:
                continue
    
    return None


def process_commoncrawl_domain(domain: str, index_ids: List[str]) -> Tuple[str, int]:
    """Process a single domain through all CommonCrawl indexes"""
    domain_temp_dir = CC_TEMP_DIR / domain
    domain_temp_dir.mkdir(parents=True, exist_ok=True)
    
    index_workers = min(MAX_INDEX_WORKERS_CAP, max(1, len(index_ids) // 4))
    temp_files = []
    
    with ThreadPoolExecutor(max_workers=index_workers) as executor:
        futures = {
            executor.submit(fetch_urls_for_index, index_id, domain, domain_temp_dir): index_id
            for index_id in index_ids
        }
        
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    temp_files.append(result)
            except Exception:
                pass
    
    urls = set()
    for file in temp_files:
        try:
            with file.open() as f:
                for line in f:
                    line = line.strip()
                    if line:
                        urls.add(line)
        except Exception:
            pass
    
    output_file = CC_DIR / f"{domain}.txt"
    with output_file.open("w") as out:
        for url in sorted(urls):
            out.write(url + "\n")
    
    # Cleanup temp files
    for file in temp_files:
        try:
            os.remove(file)
        except OSError:
            pass
    
    try:
        domain_temp_dir.rmdir()
    except OSError:
        pass
    
    return domain, len(urls)


# STAGE 3: ALIENVAULT


def fetch_alienvault_urls(domain: str) -> Set[str]:
    """Fetch URLs from AlienVault OTX for a domain"""
    page = 1
    urls = set()
    max_pages = 50  # Safety limit
    
    headers = get_api_headers()
    session = SessionManager.get_session()
    
    while page <= max_pages:
        url = (
            f"{ALIENVAULT_BASE_URL}/{domain}/url_list"
            f"?limit=500&page={page}"
        )
        
        try:
            response = session.get(
                url,
                headers=headers,
                timeout=ALIENVAULT_TIMEOUT,
                allow_redirects=True
            )
            
            if response.status_code == 429:
                time.sleep(2)
                continue
                
            if response.status_code != 200:
                return urls
            
            data = response.json()
            url_list = data.get("url_list", [])
            
            # Extract URLs from url_list - each item has a "url" field
            for entry in url_list:
                if isinstance(entry, dict) and "url" in entry:
                    extracted_url = entry["url"]
                    if isinstance(extracted_url, str) and extracted_url.strip():
                        urls.add(extracted_url.strip())
            
            has_next = data.get("has_next", False)
            
            if not has_next:
                return urls
            
            page += 1
            
        except requests.exceptions.Timeout:
            return urls
        except requests.exceptions.RequestException:
            return urls
        except json.JSONDecodeError:
            return urls
        except Exception:
            return urls
    
    return urls


def process_alienvault_domain(domain: str) -> Tuple[str, int]:
    """Process a single domain through AlienVault"""
    urls = fetch_alienvault_urls(domain)
    
    output_file = ALIENVAULT_DIR / f"{domain}.txt"
    with output_file.open("w") as f:
        for url in sorted(urls):
            f.write(url + "\n")
    
    return domain, len(urls)


# STAGE 4: URL GENERATION


def bucket_name(domain: str) -> str:
    """Extract bucket name from domain"""
    return domain.split(".", 1)[0]


def generate_urls_for_domain(domain: str, paths: List[str]) -> Tuple[str, int]:
    """Generate URLs for a domain using wordlist and cloud patterns"""
    urls = []
    
    # WEB URLS (WITH PATHS)
    for scheme in ("http", "https"):
        base = f"{scheme}://{domain}"
        for path in paths:
            urls.append(base + path)
    
    # CLOUD URLS (NO PATHS)
    bucket = bucket_name(domain)
    for pattern in CLOUD_PATTERNS:
        urls.append(pattern.format(b=bucket))
    
    output_file = GENERATED_DIR / f"{domain}.txt"
    unique_urls = sorted(set(urls))
    
    with output_file.open("w") as f:
        for url in unique_urls:
            f.write(url + "\n")
    
    return domain, len(unique_urls)


# STAGE 5: COMBINE OUTPUTS


def combine_domain_outputs(domain: str) -> Tuple[str, int]:
    """Combine all outputs for a single domain into one file"""
    combined_urls = set()
    
    # Collect from Wayback
    wayback_file = WAYBACK_DIR / f"{domain}.txt"
    if wayback_file.exists():
        with wayback_file.open(errors="ignore") as f:
            for line in f:
                url = line.strip().split()[0] if line.strip() else ""
                if url:
                    combined_urls.add(url)
    
    # Collect from CommonCrawl
    cc_file = CC_DIR / f"{domain}.txt"
    if cc_file.exists():
        with cc_file.open(errors="ignore") as f:
            for line in f:
                url = line.strip()
                if url:
                    combined_urls.add(url)
    
    # Collect from AlienVault
    av_file = ALIENVAULT_DIR / f"{domain}.txt"
    if av_file.exists():
        with av_file.open(errors="ignore") as f:
            for line in f:
                url = line.strip()
                if url:
                    combined_urls.add(url)
    
    # Collect from Generated
    gen_file = GENERATED_DIR / f"{domain}.txt"
    if gen_file.exists():
        with gen_file.open(errors="ignore") as f:
            for line in f:
                url = line.strip()
                if url:
                    combined_urls.add(url)
    
    # Write combined output
    output_file = COMBINED_DIR / f"{domain}.txt"
    with output_file.open("w") as out:
        for url in sorted(combined_urls):
            out.write(url + "\n")
    
    return domain, len(combined_urls)


# STAGE 6: FILTERING - STAGE 1


def parse_line(line: str) -> Tuple[Optional[str], Optional[int]]:
    """Parse a line that may contain URL with mime and status"""
    parts = line.strip().split()
    
    if not parts:
        return None, None
    
    url = parts[0]
    status_code = None
    
    if len(parts) >= 3:
        try:
            status_code = int(parts[-1])
        except ValueError:
            status_code = None
    
    return url, status_code


def normalize_url(url: str) -> str:
    """Normalize URL by removing tracking parameters"""
    parsed = urlparse(url)
    
    qs = parse_qs(parsed.query)
    qs = {k: v for k, v in qs.items() if k.lower() not in TRACKING_PARAMS}
    
    query = "&".join(f"{k}={v[0]}" for k, v in qs.items())
    
    clean = parsed._replace(query=query)
    return urlunparse(clean)


def should_drop(url: str) -> bool:
    """Check if URL should be dropped based on filters"""
    path = urlparse(url).path.lower()
    
    if EXTENSION_FILTER.search(path):
        return True
    if FRAMEWORK_PATHS.search(path):
        return True
    if CMS_PATHS.search(path):
        return True
    if PAGINATION.search(url):
        return True
    if STRUCTURAL_NOISE.search(path):
        return True
    if LEGAL_PATHS.search(path):
        return True
    if LANG_PATH.search(path):
        return True
    
    parsed = urlparse(url)
    for k, v in parse_qs(parsed.query).items():
        if QUERY_FILE_EXT.search("".join(v)):
            return True
    
    return False


def filter_stage1_file(file_path: Path) -> Tuple[str, int]:
    """Apply stage 1 filtering to a file"""
    output_path = FILTERED1_DIR / f"{file_path.name}"
    
    seen = set()
    kept = []
    
    with file_path.open(errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            
            url, status_code = parse_line(line)
            
            if url is None:
                continue
            
            # Filter 404s
            if status_code is not None:
                if status_code == 404:
                    continue
            
            url = normalize_url(url)
            
            if should_drop(url):
                continue
            
            if url not in seen:
                seen.add(url)
                kept.append(url)
    
    with output_path.open("w") as out:
        for u in kept:
            out.write(u + "\n")
    
    return file_path.name, len(kept)


# STAGE 7: FILTERING - STAGE 2


def path_depth(path: str) -> int:
    """Number of non-empty path segments"""
    return len([p for p in path.split("/") if p])


def canonical_key(url: str) -> str:
    """Cut URL at the LAST occurring structural separator"""
    last_pos = -1
    
    for sep in SEPARATORS:
        pos = url.rfind(sep)
        if pos > last_pos:
            last_pos = pos
    
    if last_pos == -1:
        return url
    
    return url[:last_pos + 1]


def filter_stage2_file(file_path: Path) -> Tuple[str, int]:
    """Apply stage 2 queue filtering to a file"""
    output_path = FILTERED2_DIR / f"{file_path.stem}.txt"
    
    queue = []
    queue_keys = []
    final_urls = []
    
    with file_path.open(errors="ignore") as f:
        for line in f:
            url = line.strip()
            if not url:
                continue
            
            parsed = urlparse(url)
            
            # 1-LEVEL PATHS → ALWAYS KEEP
            if path_depth(parsed.path) == 1:
                final_urls.append(url)
                continue
            
            key = canonical_key(url)
            
            # Warm-up
            if len(queue) < QUEUE_LIMIT:
                queue.append(url)
                queue_keys.append(key)
                continue
            
            matches = sum(1 for k in queue_keys if k == key)
            
            # Pure fan-out → drop
            if matches == QUEUE_LIMIT:
                continue
            
            # Release oldest
            released_url = queue.pop(0)
            queue_keys.pop(0)
            final_urls.append(released_url)
            
            queue.append(url)
            queue_keys.append(key)
    
    # Flush remaining queue
    final_urls.extend(queue)
    
    with output_path.open("w") as out:
        for u in final_urls:
            out.write(u + "\n")
    
    return file_path.name, len(final_urls)


# CONCURRENT PIPELINE COORDINATOR


class PipelineCoordinator:
    """Coordinates concurrent execution of all pipeline stages"""
    
    def __init__(self, domains: List[str], paths: List[str], cc_index_ids: List[str]):
        self.domains = domains
        self.paths = paths
        self.cc_index_ids = cc_index_ids
        
        # Track completion status per domain
        self.domain_collection_done: Dict[str, Dict[str, bool]] = {
            domain: {
                "wayback": False,
                "commoncrawl": False,
                "alienvault": False,
                "generated": False
            }
            for domain in domains
        }
        
        # Queues for pipeline stages
        self.combine_queue: Queue = Queue()
        self.filter1_queue: Queue = Queue()
        self.filter2_queue: Queue = Queue()
        
        # Results storage
        self.results: Dict[str, Dict] = {}
        self.results_lock = threading.Lock()
        
        # Final results for clean output
        self.final_results: Dict[str, int] = {}
        
        # Status flags
        self.collection_complete = threading.Event()
        self.combine_complete = threading.Event()
        self.filter1_complete = threading.Event()
    
    def mark_collection_done(self, domain: str, source: str, count: int, success: bool = True):
        """Mark a collection task as complete and trigger combine if ready"""
        with self.results_lock:
            self.domain_collection_done[domain][source] = True
            
            if domain not in self.results:
                self.results[domain] = {}
            self.results[domain][source] = {"count": count, "success": success}
            
            # Check if all sources are done for this domain
            if all(self.domain_collection_done[domain].values()):
                self.combine_queue.put(domain)
    
    def run_collectors(self, executor: ThreadPoolExecutor) -> Dict[Future, Tuple[str, str]]:
        """Submit all collection tasks and return future mapping"""
        future_to_task = {}
        
        for domain in self.domains:
            # Wayback
            future = executor.submit(fetch_wayback, domain)
            future_to_task[future] = (domain, "wayback")
            
            # CommonCrawl
            if self.cc_index_ids:
                future = executor.submit(process_commoncrawl_domain, domain, self.cc_index_ids)
                future_to_task[future] = (domain, "commoncrawl")
            else:
                self.mark_collection_done(domain, "commoncrawl", 0, False)
            
            # AlienVault
            future = executor.submit(process_alienvault_domain, domain)
            future_to_task[future] = (domain, "alienvault")
            
            # Generated URLs
            if self.paths:
                future = executor.submit(generate_urls_for_domain, domain, self.paths)
                future_to_task[future] = (domain, "generated")
            else:
                self.mark_collection_done(domain, "generated", 0, False)
        
        return future_to_task
    
    def combine_worker(self):
        """Worker that combines outputs as they become ready"""
        completed = 0
        target = len(self.domains)
        
        while completed < target:
            try:
                domain = self.combine_queue.get(timeout=2)
                
                try:
                    domain_name, count = combine_domain_outputs(domain)
                    # Queue for filtering
                    self.filter1_queue.put(COMBINED_DIR / f"{domain}.txt")
                    
                except Exception:
                    pass
                
                completed += 1
                
            except:
                # Check if we should exit
                if self.collection_complete.is_set():
                    # Give a bit more time for any pending items
                    time.sleep(0.5)
                    if self.combine_queue.empty():
                        break
        
        self.combine_complete.set()
    
    def filter1_worker(self):
        """Worker that applies stage 1 filtering as files become ready"""
        completed = 0
        target = len(self.domains)
        
        while completed < target:
            try:
                file_path = self.filter1_queue.get(timeout=2)
                
                try:
                    name, count = filter_stage1_file(file_path)
                    # Queue for stage 2 filtering
                    self.filter2_queue.put(FILTERED1_DIR / name)
                    
                except Exception:
                    pass
                
                completed += 1
                
            except:
                # Check if we should exit
                if self.combine_complete.is_set():
                    time.sleep(0.5)
                    if self.filter1_queue.empty():
                        break
        
        self.filter1_complete.set()
    
    def filter2_worker(self):
        """Worker that applies stage 2 filtering as files become ready"""
        completed = 0
        target = len(self.domains)
        
        while completed < target:
            try:
                file_path = self.filter2_queue.get(timeout=2)
                
                try:
                    name, count = filter_stage2_file(file_path)
                    
                    # Store final result
                    domain = file_path.stem
                    with self.results_lock:
                        self.final_results[domain] = count
                    
                except Exception:
                    pass
                
                completed += 1
                
            except:
                # Check if we should exit
                if self.filter1_complete.is_set():
                    time.sleep(0.5)
                    if self.filter2_queue.empty():
                        break



# MAIN COLLECTION PIPELINE


def run_collection_pipeline(domains: List[str], config: Optional[Dict] = None):
    """
    Main collection pipeline that runs all stages concurrently
    
    Args:
        domains: list[str] - List of domains to process
        config: dict - Configuration options (currently unused, for future extension)
    
    Returns:
        Path to final output directory
    """
    
    if not isinstance(domains, list):
        raise TypeError("domains must be a list")
    
    if not domains:
        raise ValueError("domains list cannot be empty")
    
    start_time = time.time()
    
    safe_print("="*60)
    safe_print(f"Starting URL Collection Pipeline for {len(domains)} domain(s)")
    safe_print("="*60)
    
    # Create all necessary directories
    for directory in [WAYBACK_DIR, CC_DIR, CC_TEMP_DIR, ALIENVAULT_DIR, 
                      GENERATED_DIR, COMBINED_DIR, FILTERED1_DIR, FILTERED2_DIR]:
        directory.mkdir(parents=True, exist_ok=True)
    
    # Load wordlist for URL generation
    wordlist_path = Path("advanced-wordlist.txt")
    if not wordlist_path.exists():
        paths = []
    else:
        with wordlist_path.open() as f:
            paths = [p.strip() for p in f.readlines() if p.strip()]
            paths = [p if p.startswith("/") else "/" + p for p in paths]
    
    # Fetch CommonCrawl index IDs (only latest)
    try:
        cc_index_ids = fetch_index_ids()
    except Exception:
        cc_index_ids = []
    
    # Initialize coordinator
    coordinator = PipelineCoordinator(domains, paths, cc_index_ids)
    
    # Calculate optimal worker count
    num_collection_workers = min(MAX_DOMAIN_WORKERS, len(domains) * 4)
    
    # Start all workers
    with ThreadPoolExecutor(max_workers=num_collection_workers + 3) as executor:
        
        # Start pipeline workers
        combine_future = executor.submit(coordinator.combine_worker)
        filter1_future = executor.submit(coordinator.filter1_worker)
        filter2_future = executor.submit(coordinator.filter2_worker)
        
        # Submit all collection tasks
        future_to_task = coordinator.run_collectors(executor)
        
        # Process collection results as they complete (silently)
        for future in as_completed(future_to_task):
            domain, source = future_to_task[future]
            
            try:
                result = future.result()
                
                if source == "wayback":
                    domain_name, success, count = result
                    coordinator.mark_collection_done(domain, source, count, success)
                else:
                    domain_name, count = result
                    coordinator.mark_collection_done(domain, source, count, True)
                    
            except Exception:
                coordinator.mark_collection_done(domain, source, 0, False)
        
        # Signal that collection is complete
        coordinator.collection_complete.set()
        
        # Wait for pipeline workers to complete
        combine_future.result()
        filter1_future.result()
        filter2_future.result()
    
    # Print clean summary
    safe_print("\n" + "="*60)
    safe_print("URL Collection Results:")
    safe_print("="*60)
    
    # Sort domains and print results
    for domain in sorted(coordinator.final_results.keys()):
        count = coordinator.final_results[domain]
        safe_print(f"{domain}: {count} URLs collected")
    
    elapsed = time.time() - start_time
    safe_print("="*60)
    safe_print(f"Pipeline Complete in {elapsed:.2f} seconds")
    safe_print(f"Collected and filtered URLs for next step: {FILTERED2_DIR}")
    safe_print("="*60 + "\n")

    # Cleanup temporary directories
    try:
        import shutil
        if BASE_TEMP_DIR.exists():
            shutil.rmtree(BASE_TEMP_DIR)
    except Exception:
        pass
    
    return FILTERED2_DIR



# CLI ENTRY POINT


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Use command line arguments as domains
        test_domains = sys.argv[1:]
    else:
        # Default test domain
        test_domains = ["yourdost.com"]
    
    run_collection_pipeline(test_domains)
