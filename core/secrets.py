# core/secrets.py
import re
import logging
from .config import config
from .database import db

logger = logging.getLogger(__name__)


class SecretScanner:
    """Secret detection and management."""
    
    @staticmethod
    def mask_secret(secret, mask_percent=70):
        """Mask a percentage of the secret string."""
        if not secret:
            return secret
        mask_chars = int(len(secret) * mask_percent / 100)
        return secret[:len(secret)-mask_chars] + '*' * mask_chars
    
    @staticmethod
    def scan_for_secrets(content, domain, js_url, sha1):
        """Scan content for secrets using regex patterns."""
        findings = []
        
        if not content:
            return findings
        
        try:
            content_str = content.decode('utf-8', errors='ignore')
            
            for rule in config.rules:
                try:
                    pattern = re.compile(rule['pattern'])
                    matches = pattern.finditer(content_str)
                    
                    for match in matches:
                        excerpt = match.group(0)
                        # Basic length filter to reduce false positives
                        if len(excerpt) >= 10:
                            # Mask the secret before storing
                            masked_excerpt = SecretScanner.mask_secret(
                                excerpt, 
                                config.mask_percent
                            )
                            
                            # Add to database
                            db.add_finding(domain, js_url, sha1, rule['id'], masked_excerpt)
                            
                            # Add to findings list
                            findings.append({
                                'rule_id': rule['id'],
                                'excerpt': (masked_excerpt[:100] + '...' 
                                          if len(masked_excerpt) > 100 
                                          else masked_excerpt)
                            })
                            
                except Exception as e:
                    logger.error(f"Error with rule {rule.get('id', 'unknown')}: {e}")
                    
        except Exception as e:
            logger.error(f"Error scanning content for secrets: {e}")
        
        return findings


# Global secret scanner instance
secret_scanner = SecretScanner()