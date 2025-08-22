#!/usr/bin/env python3
# download_domains.py - Download top 1000 domains for JS scanner

import requests
import zipfile
import csv
import io
import sys
from datetime import datetime


def download_cisco_umbrella_domains(count=1000):
    """Download domains from Cisco Umbrella top 1M list."""
    url = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
    
    try:
        print("Downloading Cisco Umbrella top 1M domains...")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        # Extract ZIP file
        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
            # Find the CSV file in the ZIP
            csv_filename = next(name for name in zip_file.namelist() if name.endswith('.csv'))
            
            with zip_file.open(csv_filename) as csv_file:
                csv_content = csv_file.read().decode('utf-8')
        
        # Parse CSV and extract domains
        domains = []
        reader = csv.reader(io.StringIO(csv_content))
        
        for i, row in enumerate(reader):
            if i >= count:  # Stop after getting required count
                break
            
            if len(row) >= 2 and row[1]:  # Ensure we have rank and domain
                domain = row[1].strip()
                # Filter out TLDs and invalid domains
                if '.' in domain and not domain.startswith('.') and len(domain) > 3:
                    domains.append(domain)
        
        return domains[:count]  # Ensure we don't exceed count
        
    except Exception as e:
        print(f"Error downloading Cisco Umbrella domains: {e}")
        return None


def download_majestic_million_domains(count=1000):
    """Download domains from Majestic Million list."""
    url = "https://downloads.majestic.com/majestic_million.csv"
    
    try:
        print("Downloading Majestic Million domains...")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        # Parse CSV
        domains = []
        reader = csv.reader(io.StringIO(response.text))
        
        # Skip header
        next(reader, None)
        
        for i, row in enumerate(reader):
            if i >= count:
                break
            
            if len(row) >= 3 and row[2]:  # Domain is in 3rd column
                domain = row[2].strip()
                if '.' in domain and not domain.startswith('.') and len(domain) > 3:
                    domains.append(domain)
        
        return domains[:count]
        
    except Exception as e:
        print(f"Error downloading Majestic Million domains: {e}")
        return None


def filter_domains(domains):
    """Filter domains to remove problematic ones for scanning."""
    filtered = []
    
    # Domains to skip (known to be problematic for automated scanning)
    skip_patterns = [
        'localhost',
        '127.0.0.1',
        'example.com',
        'test.com',
        '.local',
        '.internal'
    ]
    
    for domain in domains:
        # Skip if domain matches any skip pattern
        if any(pattern in domain.lower() for pattern in skip_patterns):
            continue
        
        # Skip if domain is too short or doesn't have proper format
        if len(domain) < 4 or domain.count('.') == 0:
            continue
        
        # Skip if domain starts with non-alphabetic character
        if not domain[0].isalpha():
            continue
            
        filtered.append(domain)
    
    return filtered


def save_domains_file(domains, filename="domains.txt"):
    """Save domains to file with header."""
    try:
        with open(filename, 'w') as f:
            # Write header
            f.write("# Top 1000 domains for JavaScript Security Scanner\n")
            f.write(f"# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("# Source: Cisco Umbrella Top 1M Domains List\n")
            f.write("# Format: one domain per line, comments start with #\n\n")
            
            # Write domains
            for domain in domains:
                f.write(f"{domain}\n")
        
        print(f"✅ Successfully saved {len(domains)} domains to {filename}")
        return True
        
    except Exception as e:
        print(f"Error saving domains file: {e}")
        return False


def main():
    """Main function to download and save domains."""
    count = 1000
    
    # Try Cisco Umbrella first (most reliable)
    print("Attempting to download from Cisco Umbrella...")
    domains = download_cisco_umbrella_domains(count)
    
    # Fallback to Majestic Million if Cisco fails
    if not domains:
        print("Cisco Umbrella failed, trying Majestic Million...")
        domains = download_majestic_million_domains(count)
    
    if not domains:
        print("❌ Failed to download domains from all sources")
        sys.exit(1)
    
    # Filter domains
    filtered_domains = filter_domains(domains)
    
    if len(filtered_domains) < count:
        print(f"Warning: Only got {len(filtered_domains)} valid domains (wanted {count})")
    
    # Save to file
    if save_domains_file(filtered_domains):
        print(f"✅ Domain extraction completed!")
        print(f"📁 File: domains.txt")
        print(f"📊 Domains: {len(filtered_domains)}")
        print(f"🔍 Ready for scanning with: python scanner.py --domains domains.txt")
    else:
        print("❌ Failed to save domains file")
        sys.exit(1)


if __name__ == "__main__":
    main()