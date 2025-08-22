# core/utils.py
import os
import hashlib
import gzip
import aiofiles
import tldextract
import re
import logging
from urllib.parse import urlparse, urljoin
from .config import config

logger = logging.getLogger(__name__)


class Utils:
    """Utility functions for the scanner."""
    
    @staticmethod
    def sha1_bytes(content: bytes) -> str:
        """Calculate SHA1 hash of bytes content."""
        return hashlib.sha1(content).hexdigest()
    
    @staticmethod
    async def save_blob(content: bytes, sha1: str):
        """Save blob content to gzipped file."""
        path = os.path.join(config.BLOBS_DIR, sha1[:2])
        os.makedirs(path, exist_ok=True)
        file_path = os.path.join(path, f"{sha1}.js.gz")
        
        async with aiofiles.open(file_path, "wb") as f:
            compressed = gzip.compress(content)
            await f.write(compressed)
        
        return file_path
    
    @staticmethod
    def is_vendor_js(domain: str, js_url: str) -> bool:
        """Determine if JS file is from a vendor/third-party."""
        try:
            js_domain = tldextract.extract(urlparse(js_url).netloc).registered_domain
            page_domain = tldextract.extract(domain).registered_domain
            
            # Different domains = vendor
            if js_domain and page_domain and js_domain != page_domain:
                return True
            
            # Check for vendor keywords
            vendor_keywords = [
                "react", "jquery", "bootstrap", "vue", "angular", "moment", "lodash", "sentry",
                "gtag", "analytics", "hotjar", "stripe", "paypal", "recaptcha", "cloudflare"
            ]
            
            # Check for vendor paths
            vendor_paths = ["/vendor/", "/lib/", "/node_modules/", "/cdn/"]
            
            js_url_lower = js_url.lower()
            if any(k in js_url_lower for k in vendor_keywords):
                return True
            
            if any(x in js_url_lower for x in vendor_paths):
                return True
                
        except Exception as e:
            logger.error(f"Error in vendor detection for {js_url}: {e}")
        
        return False
    
    @staticmethod
    async def extract_js_urls(session, domain):
        """Extract JS URLs from a domain's homepage."""
        url = f"https://{domain}" if not domain.startswith(('http://', 'https://')) else domain
        headers = {'User-Agent': config.user_agent}
        
        try:
            async with session.get(url, headers=headers, timeout=config.timeout_secs) as response:
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
    
    @staticmethod
    async def fetch_js(session, url, etag=None, last_modified=None):
        """Fetch JS content with conditional requests."""
        headers = {'User-Agent': config.user_agent}
        if etag:
            headers['If-None-Match'] = etag
        if last_modified:
            headers['If-Modified-Since'] = last_modified
        
        try:
            async with session.get(url, headers=headers, timeout=config.timeout_secs) as resp:
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
    
    @staticmethod
    async def load_blob_content(sha1: str):
        """Load content from blob storage."""
        blob_path = os.path.join(config.BLOBS_DIR, sha1[:2], f"{sha1}.js.gz")
        if os.path.exists(blob_path):
            async with aiofiles.open(blob_path, "rb") as f:
                compressed = await f.read()
                return gzip.decompress(compressed)
        return None


# Global utils instance
utils = Utils()