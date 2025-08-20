import os
import asyncio
import aiohttp
import aiofiles
import hashlib
import gzip
import sqlite3
import yaml
import tldextract
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse
from dotenv import load_dotenv
import logging

# -----------------------------
# Setup logging
# -----------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# -----------------------------
# Load ENV + CONFIG + RULES
# -----------------------------
load_dotenv()

DB_PATH = os.getenv("DB_PATH", "storage/db.sqlite")
BLOBS_DIR = os.getenv("BLOBS_DIR", "storage/blobs")

with open("config.yaml", "r") as f:
    CONFIG = yaml.safe_load(f)

with open("rules.yaml", "r") as f:
    RULES_CONFIG = yaml.safe_load(f)

# -----------------------------
# DB Init (SQLite for now)
# -----------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # assets table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        domain TEXT,
        js_url TEXT,
        latest_sha1 TEXT,
        latest_etag TEXT,
        latest_last_modified TEXT,
        is_vendor INTEGER,
        last_seen_at TEXT,
        PRIMARY KEY (domain, js_url)
    )
    """)

    # findings table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT,
        js_url TEXT,
        sha1 TEXT,
        rule_id TEXT,
        excerpt TEXT,
        ts TEXT
    )
    """)

    conn.commit()
    conn.close()

# -----------------------------
# Database helper functions
# -----------------------------
def get_asset(domain, js_url):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT * FROM assets WHERE domain = ? AND js_url = ?", (domain, js_url))
    row = cur.fetchone()
    conn.close()
    
    if row:
        return {
            'domain': row[0],
            'js_url': row[1],
            'latest_sha1': row[2],
            'latest_etag': row[3],
            'latest_last_modified': row[4],
            'is_vendor': bool(row[5]),
            'last_seen_at': row[6]
        }
    return None

def update_asset(domain, js_url, sha1, etag, last_modified, is_vendor):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Check if asset exists
    asset = get_asset(domain, js_url)
    current_time = datetime.now().isoformat()
    
    if asset:
        # Update existing asset
        cur.execute("""
        UPDATE assets 
        SET latest_sha1 = ?, latest_etag = ?, latest_last_modified = ?, is_vendor = ?, last_seen_at = ?
        WHERE domain = ? AND js_url = ?
        """, (sha1, etag, last_modified, int(is_vendor), current_time, domain, js_url))
    else:
        # Insert new asset
        cur.execute("""
        INSERT INTO assets (domain, js_url, latest_sha1, latest_etag, latest_last_modified, is_vendor, last_seen_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (domain, js_url, sha1, etag, last_modified, int(is_vendor), current_time))
    
    conn.commit()
    conn.close()

def add_finding(domain, js_url, sha1, rule_id, excerpt):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    current_time = datetime.now().isoformat()
    
    cur.execute("""
    INSERT INTO findings (domain, js_url, sha1, rule_id, excerpt, ts)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (domain, js_url, sha1, rule_id, excerpt, current_time))
    
    conn.commit()
    conn.close()

# -----------------------------
# SHA1 Hash helper
# -----------------------------
def sha1_bytes(content: bytes) -> str:
    return hashlib.sha1(content).hexdigest()

# -----------------------------
# Secret masking helper
# -----------------------------
def mask_secret(secret, mask_percent=70):
    """Mask a percentage of the secret string"""
    if not secret:
        return secret
    mask_chars = int(len(secret) * mask_percent / 100)
    return secret[:len(secret)-mask_chars] + '*' * mask_chars

# -----------------------------
# Save blob (gzip)
# -----------------------------
async def save_blob(content: bytes, sha1: str):
    path = os.path.join(BLOBS_DIR, sha1[:2])
    os.makedirs(path, exist_ok=True)
    file_path = os.path.join(path, f"{sha1}.js.gz")
    
    async with aiofiles.open(file_path, "wb") as f:
        compressed = gzip.compress(content)
        await f.write(compressed)
    
    return file_path

# -----------------------------
# Vendor heuristic
# -----------------------------
def is_vendor_js(domain: str, js_url: str) -> bool:
    try:
        js_domain = tldextract.extract(urlparse(js_url).netloc).registered_domain
        page_domain = tldextract.extract(domain).registered_domain
        
        if js_domain and page_domain and js_domain != page_domain:
            return True
        
        vendor_keywords = [
            "react", "jquery", "bootstrap", "vue", "angular", "moment", "lodash", "sentry",
            "gtag", "analytics", "hotjar", "stripe", "paypal", "recaptcha", "cloudflare"
        ]
        
        vendor_paths = ["/vendor/", "/lib/", "/node_modules/", "/cdn/"]
        
        js_url_lower = js_url.lower()
        if any(k in js_url_lower for k in vendor_keywords):
            return True
        
        if any(x in js_url_lower for x in vendor_paths):
            return True
            
    except Exception as e:
        logger.error(f"Error in vendor detection for {js_url}: {e}")
    
    return False

# -----------------------------
# Extract JS URLs from HTML
# -----------------------------
async def extract_js_urls(session, domain):
    """Extract JS URLs from a domain's homepage"""
    url = f"https://{domain}" if not domain.startswith(('http://', 'https://')) else domain
    headers = {'User-Agent': CONFIG['user_agent']}
    
    try:
        async with session.get(url, headers=headers, timeout=CONFIG["timeout_secs"]) as response:
            if response.status == 200:
                html = await response.text()
                
                # Simple regex to find JS files
                js_pattern = r'<script[^>]+src=["\']([^"\']+\.js)["\']'
                js_urls = re.findall(js_pattern, html, re.IGNORECASE)
                
                # Convert relative URLs to absolute
                full_js_urls = [urljoin(url, js_url) for js_url in js_urls]
                return full_js_urls
                
    except Exception as e:
        logger.error(f"Error extracting JS URLs from {domain}: {e}")
    
    return []

# -----------------------------
# Fetch JS with conditional requests
# -----------------------------
async def fetch_js(session, url, etag=None, last_modified=None):
    headers = {'User-Agent': CONFIG['user_agent']}
    if etag:
        headers['If-None-Match'] = etag
    if last_modified:
        headers['If-Modified-Since'] = last_modified
    
    try:
        async with session.get(url, headers=headers, timeout=CONFIG["timeout_secs"]) as resp:
            if resp.status == 304:  # Not Modified
                return None, resp.headers, True
            elif resp.status == 200:
                content = await resp.read()
                return content, resp.headers, False
            else:
                logger.warning(f"Failed to fetch {url}: Status {resp.status}")
                return None, resp.headers, False
                
    except Exception as e:
        logger.error(f"Error fetching {url}: {e}")
        return None, None, False

# -----------------------------
# Scan content for secrets
# -----------------------------
def scan_for_secrets(content, domain, js_url, sha1):
    """Scan content for secrets using regex patterns"""
    findings = []
    
    if not content:
        return findings
    
    try:
        content_str = content.decode('utf-8', errors='ignore')
        
        for rule in RULES_CONFIG['rules']:
            try:
                pattern = re.compile(rule['pattern'])
                matches = pattern.finditer(content_str)
                
                for match in matches:
                    excerpt = match.group(0)
                    # Basic length filter to reduce false positives
                    if len(excerpt) >= 10:
                        # Mask the secret before storing
                        masked_excerpt = mask_secret(excerpt, RULES_CONFIG.get('mask_percent', 70))
                        
                        add_finding(domain, js_url, sha1, rule['id'], masked_excerpt)
                        findings.append({
                            'rule_id': rule['id'],
                            'excerpt': masked_excerpt[:100] + '...' if len(masked_excerpt) > 100 else masked_excerpt
                        })
                        
            except Exception as e:
                logger.error(f"Error with rule {rule.get('id', 'unknown')}: {e}")
                
    except Exception as e:
        logger.error(f"Error scanning content for secrets: {e}")
    
    return findings

# -----------------------------
# Process a single JS file
# -----------------------------
async def process_js_file(session, domain, js_url):
    """Process a single JS file with diff logic"""
    logger.info(f"Processing JS: {js_url}")
    
    # Check if we have this file in database
    asset = get_asset(domain, js_url)
    
    # Prepare conditional request headers
    etag = asset['latest_etag'] if asset else None
    last_modified = asset['latest_last_modified'] if asset else None
    
    # Fetch the JS content
    content, headers, not_modified = await fetch_js(session, js_url, etag, last_modified)
    
    if not_modified:
        logger.info(f"JS unchanged (304): {js_url}")
        # Update last seen time
        update_asset(domain, js_url, 
                    asset['latest_sha1'], 
                    asset['latest_etag'], 
                    asset['latest_last_modified'], 
                    asset['is_vendor'])
        return asset['latest_sha1'], True  # unchanged
    
    if not content:
        logger.warning(f"Failed to fetch JS content: {js_url}")
        return None, False
    
    # Calculate SHA1 hash
    sha1 = sha1_bytes(content)
    
    # Check if content is unchanged by comparing SHA1
    if asset and asset['latest_sha1'] == sha1:
        logger.info(f"JS unchanged (same hash): {js_url}")
        update_asset(domain, js_url, sha1, 
                    headers.get('ETag'), 
                    headers.get('Last-Modified'), 
                    asset['is_vendor'])
        return sha1, True  # unchanged
    
    # Determine if this is a vendor file
    is_vendor = is_vendor_js(domain, js_url)
    
    # Update database
    update_asset(domain, js_url, sha1, 
                headers.get('ETag'), 
                headers.get('Last-Modified'), 
                is_vendor)
    
    # Only process custom files (non-vendor)
    if not is_vendor:
        # Save content
        await save_blob(content, sha1)
        
        # Scan for secrets if file changed
        findings = scan_for_secrets(content, domain, js_url, sha1)
        if findings:
            logger.info(f"Found {len(findings)} secrets in {js_url}")
    
    return sha1, False  # changed or new

# -----------------------------
# Main scanner for a domain
# -----------------------------
async def scan_domain(session, domain):
    """Scan a single domain"""
    logger.info(f"Scanning domain: {domain}")
    
    try:
        # Extract JS URLs from homepage
        js_urls = await extract_js_urls(session, domain)
        if not js_urls:
            logger.warning(f"No JS files found for {domain}")
            return
        
        logger.info(f"Found {len(js_urls)} JS files for {domain}")
        
        # Process each JS file
        for js_url in js_urls:
            try:
                sha1, unchanged = await process_js_file(session, domain, js_url)
                
                # If file is unchanged but we need to rescan secrets
                if (unchanged and CONFIG.get('rescan_unchanged_secret_check', False) and sha1):
                    # Load content from blob and rescan
                    blob_path = os.path.join(BLOBS_DIR, sha1[:2], f"{sha1}.js.gz")
                    if os.path.exists(blob_path):
                        async with aiofiles.open(blob_path, "rb") as f:
                            compressed = await f.read()
                            content = gzip.decompress(compressed)
                            scan_for_secrets(content, domain, js_url, sha1)
                            
            except Exception as e:
                logger.error(f"Error processing JS file {js_url}: {e}")
                
    except Exception as e:
        logger.error(f"Error scanning domain {domain}: {e}")

# -----------------------------
# Main function
# -----------------------------
async def main(domains_file, once=False):
    """Main function"""
    init_db()
    
    # Read domains
    with open(domains_file, "r") as f:
        domains = [d.strip() for d in f if d.strip() and not d.startswith('#')]
    
    logger.info(f"Loaded {len(domains)} domains")
    
    # HTTP session
    connector = aiohttp.TCPConnector(
        limit=CONFIG["concurrency"],
        limit_per_host=CONFIG.get("per_domain_rate_limit", 2)
    )
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [scan_domain(session, d) for d in domains]
        await asyncio.gather(*tasks)
    
    if once:
        logger.info("One-time scan completed")
    else:
        logger.info(f"Scan completed. Next scan in {CONFIG['scan_interval_hours']} hours")
        await asyncio.sleep(CONFIG['scan_interval_hours'] * 3600)
        await main(domains_file, once)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--domains", default="domains.txt", help="domains.txt file")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    args = parser.parse_args()

    asyncio.run(main(args.domains, args.once))