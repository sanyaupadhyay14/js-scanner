# core/scanner.py
import logging
from .config import config
from .database import db
from .utils import utils
from .secrets import secret_scanner

logger = logging.getLogger(__name__)


class JSScanner:
    """Main JavaScript scanner logic."""
    
    @staticmethod
    async def process_js_file(session, domain, js_url):
        """Process a single JS file with diff logic."""
        logger.info(f"Processing JS: {js_url}")
        
        # Check if we have this file in database
        asset = db.get_asset(domain, js_url)
        
        # Prepare conditional request headers
        etag = asset['latest_etag'] if asset else None
        last_modified = asset['latest_last_modified'] if asset else None
        
        # Fetch the JS content
        content, headers, not_modified = await utils.fetch_js(session, js_url, etag, last_modified)
        
        if not_modified:
            logger.info(f"JS unchanged (304): {js_url}")
            # Update last seen time
            db.update_asset(domain, js_url, 
                          asset['latest_sha1'], 
                          asset['latest_etag'], 
                          asset['latest_last_modified'], 
                          asset['is_vendor'],
                          change_status='unchanged')
            return asset['latest_sha1'], True  # unchanged
        
        if not content:
            logger.warning(f"Failed to fetch JS content: {js_url}")
            return None, False
        
        # Calculate SHA1 hash
        sha1 = utils.sha1_bytes(content)
        
        # Check if content is unchanged by comparing SHA1
        if asset and asset['latest_sha1'] == sha1:
            logger.info(f"JS unchanged (same hash): {js_url}")
            db.update_asset(domain, js_url, sha1, 
                          headers.get('ETag'), 
                          headers.get('Last-Modified'), 
                          asset['is_vendor'],
                          change_status='unchanged')
            return sha1, True  # unchanged
        
        # Determine if this is a vendor file
        is_vendor = utils.is_vendor_js(domain, js_url)
        # Set appropriate change status
        change_status = 'changed' if asset else 'new'
        # Update database
        db.update_asset(domain, js_url, sha1, 
                      headers.get('ETag'), 
                      headers.get('Last-Modified'), 
                      is_vendor,
                      change_status=change_status)

        
        # Only process custom files (non-vendor)
        if not is_vendor:
            # Save content
            await utils.save_blob(content, sha1)
            
            # Scan for secrets if file changed
            findings = secret_scanner.scan_for_secrets(content, domain, js_url, sha1)
            if findings:
                logger.info(f"Found {len(findings)} secrets in {js_url}")
        
        return sha1, False  # changed or new
    
    @staticmethod
    async def scan_domain(session, domain):
        """Scan a single domain."""
        logger.info(f"Scanning domain: {domain}")
        
        try:
            # Extract JS URLs from homepage
            js_urls = await utils.extract_js_urls(session, domain)
            if not js_urls:
                logger.warning(f"No JS files found for {domain}")
                return
            
            logger.info(f"Found {len(js_urls)} JS files for {domain}")
            
            # Process each JS file
            for js_url in js_urls:
                try:
                    sha1, unchanged = await JSScanner.process_js_file(session, domain, js_url)
                    
                    # If file is unchanged but we need to rescan secrets
                    if (unchanged and config.rescan_unchanged_secret_check and sha1):
                        # Load content from blob and rescan
                        content = await utils.load_blob_content(sha1)
                        if content:
                            secret_scanner.scan_for_secrets(content, domain, js_url, sha1)
                            
                except Exception as e:
                    logger.error(f"Error processing JS file {js_url}: {e}")
                    
        except Exception as e:
            logger.error(f"Error scanning domain {domain}: {e}")


# Global scanner instance
js_scanner = JSScanner()