# JS Scanner

A production-ready service that efficiently scans websites for JavaScript files, intelligently skips common third-party libraries, and detects potential secrets. Built with Python, AsyncIO, and PostgreSQL for high performance and reliability.

## Features

- **Smart Differential Scanning**: Uses ETag/Last-Modified headers and SHA-1 hashing to avoid re-processing unchanged files, saving ~90% bandwidth on subsequent runs
- **Vendor Intelligence**: Automatically skips 3rd-party libraries (React, jQuery, Bootstrap, etc.) using domain and path heuristics
- **Secret Detection**: Scans custom JS for exposed secrets using configurable regex patterns
- **PostgreSQL Storage**: Production-ready data persistence with proper schema design
- **Configurable & Scalable**: Easy concurrency controls and built for horizontal scaling

## Complete Setup & Usage Guide

### 1. Installation & First Run

```bash
# 1. Clone and enter the project
git clone https://github.com/sanyaupadhyay14/js-scanner.git
cd js-scanner

# 2. Create virtual environment and install dependencies
python -m venv venv
source venv/bin/activate  
pip install -r requirements.txt

# 3. Setup PostgreSQL database (ensure PostgreSQL is running)
createdb scannerdb

# 4. Configure environment
cp .env.example .env
# Edit .env with your PostgreSQL credentials: DB_USER, DB_PASSWORD, etc.

# 5. Edit domain.txt and add (one domain per line)
"instagram.com"
"github.com" 
"netflix.com" 

# 6. Run your first scan
python scanner.py --domains domains.txt --once

# 7. Check the results
python show_stats.py -a  # Show total files, vendor skipped, custom processed
python show_stats.py -f  # Show number of secret findings
python show_stats.py -c  # Show changed vs unchanged files

# 8. See the diff logic in action by running a second scan
python scanner.py --domains domains.txt --once 2>&1 | grep -E "(unchanged|304|same hash|skipping)"

# 9. Query the database directly to see raw data
psql -h localhost -p 5432 -U sanyakumari -d scannerdb 
\dt  # Show all tables
SELECT * FROM findings LIMIT 10;  # See first 10 findings
SELECT * FROM assets LIMIT 10;  # See first 10 assets

# 10. For continuous scanning (runs every 6 hours)
python scanner.py --domains domains.txt
# Press Ctrl+C to stop continuous scanning

## Performance Benchmarks:

Test Environment: 1000 domains, 64 concurrent connections, 2 reqs/domain limit
Initial Run: 15 minutes
Vendor Filtering: Typically 50-60% of files automatically skipped
Stats Example:
On a scan of 1000 domains, the scanner identified 915 JavaScript files and automatically skipped 481 (52.5%) as vendor libraries, processing only the 434 custom files that might contain actual secrets

## Project Architecture:
js-scanner/
├── core/                 # Application logic
│   ├── scanner.py        # Scanning orchestration
│   ├── database.py       # PostgreSQL models & operations
│   ├── utils.py          # Helpers (hashing, fetching, vendor detection)
│   ├── secrets.py        # Secret scanning
│   └── config.py         # Configuration loader
├── scanner.py            # Main CLI entry point
├── show_stats.py         # Results visualization utility
├── domains.txt           # Input domains
├── config.yaml           # Scanner configuration
├── rules.yaml            # Secret detection rules
└── requirements.txt      # Python dependencies

