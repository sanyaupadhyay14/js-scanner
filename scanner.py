#!/usr/bin/env python3
# scanner.py - Main JavaScript Scanner Application

import asyncio
import aiohttp
import logging
import argparse
from core.config import config
from core.database import db
from core.scanner import js_scanner

logger = logging.getLogger(__name__)


async def main(domains_file, once=False):
    """Main function to run the scanner."""
    # Initialize database
    db.init_db()
    
    # Read domains from file
    try:
        with open(domains_file, "r") as f:
            domains = [d.strip() for d in f if d.strip() and not d.startswith('#')]
    except FileNotFoundError:
        logger.error(f"Domains file {domains_file} not found")
        return
    except Exception as e:
        logger.error(f"Error reading domains file: {e}")
        return
    
    logger.info(f"Loaded {len(domains)} domains")
    
    if not domains:
        logger.warning("No domains to scan")
        return
    
    # Setup HTTP session with connection limits
    connector = aiohttp.TCPConnector(
        limit=config.concurrency,
        limit_per_host=config.per_domain_rate_limit
    )
    
    async with aiohttp.ClientSession(connector=connector) as session:
        # Create scanning tasks for all domains
        tasks = [js_scanner.scan_domain(session, domain) for domain in domains]
        
        # Run all tasks concurrently
        await asyncio.gather(*tasks, return_exceptions=True)
    
    if once:
        logger.info("One-time scan completed")
    else:
        logger.info(f"Scan completed. Next scan in {config.scan_interval_hours} hours")
        await asyncio.sleep(config.scan_interval_hours * 3600)
        # Recursive call for continuous scanning
        await main(domains_file, once)


def setup_logging():
    """Setup application logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('scanner.log')
        ]
    )


if __name__ == "__main__":
    # Setup command line arguments
    parser = argparse.ArgumentParser(description="JavaScript Security Scanner")
    parser.add_argument(
        "--domains", 
        default="domains.txt", 
        help="Path to domains file (default: domains.txt)"
    )
    parser.add_argument(
        "--once", 
        action="store_true", 
        help="Run scan once and exit (default: continuous scanning)"
    )
    parser.add_argument(
        "--log-level",
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help="Set logging level (default: INFO)"
    )
    
    args = parser.parse_args()
    
    # Setup logging with specified level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    setup_logging()
    
    logger.info("Starting JavaScript Security Scanner")
    logger.info(f"Database URL: {config.get_database_url()}")
    logger.info(f"Domains file: {args.domains}")
    logger.info(f"Run once: {args.once}")
    
    try:
        # Run the main scanner
        asyncio.run(main(args.domains, args.once))
    except KeyboardInterrupt:
        logger.info("Scanner interrupted by user")
    except Exception as e:
        logger.error(f"Scanner failed with error: {e}")
        raise