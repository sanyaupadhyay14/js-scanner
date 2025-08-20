# JS Scan (Minimal)

A lightweight service that scans homepage JavaScript files for domains, skips vendor libraries, computes SHA-1 hashes of custom JS files, and detects potential secrets using regex patterns. Includes intelligent diff logic to avoid re-processing unchanged files.

## ✨ Features

- **Domain Scanning**: Processes domains from a text file (one per line)
- **JS Extraction**: Automatically extracts JavaScript URLs from homepage HTML
- **Vendor Detection**: Skips common vendor libraries using smart heuristics
- **Diff Logic**: Uses ETag/Last-Modified headers and SHA-1 hashing to skip unchanged files
- **Secret Scanning**: Detects potential secrets using configurable regex patterns
- **Data Storage**: SQLite database for metadata + gzipped blob storage for custom JS files
- **Scheduling**: Configurable scan intervals (default: every 6 hours)

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- pip package manager

### Installation

1. **Clone or download the project**
   ```bash
   cd js-scan