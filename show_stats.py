#!/usr/bin/env python3
# show_stats.py - Display scanner statistics with options

import argparse
from core.database import Session, Asset, Finding

def show_asset_stats():
    """Show asset statistics (total, vendor, custom)"""
    session = Session()
    try:
        total = session.query(Asset).count()
        vendor = session.query(Asset).filter_by(is_vendor=True).count()
        custom = session.query(Asset).filter_by(is_vendor=False).count()
        
        print("📊 FILE STATS:")
        print(f"   Total: {total} JS files")
        print(f"   Vendor: {vendor} skipped")
        print(f"   Custom: {custom} processed")
    finally:
        session.close()

def show_finding_stats():
    """Show secret findings statistics"""
    session = Session()
    try:
        findings = session.query(Finding).count()
        print("🔍 SECRET FINDINGS:")
        print(f"   Findings: {findings}")
        print("   (0 is good - means no exposed secrets)")
    finally:
        session.close()

def show_change_stats():
    """Show changed vs unchanged statistics"""
    session = Session()
    try:
        assets = session.query(Asset).all()
        changed = sum(1 for a in assets if 'unchanged' not in str(a.latest_etag))
        unchanged = len(assets) - changed
        efficiency = (unchanged / len(assets)) * 100 if assets else 0
        
        print("🔄 CHANGE TRACKING:")
        print(f"   Changed: {changed}")
        print(f"   Unchanged: {unchanged}")
        print(f"   Efficiency: {efficiency:.1f}% unchanged")
    finally:
        session.close()

def show_all_stats():
    """Show all statistics"""
    print("=== JS SCANNER STATISTICS ===")
    print()
    show_asset_stats()
    print()
    show_finding_stats()
    print()
    show_change_stats()
    print()
    print("=== END OF STATISTICS ===")

def main():
    parser = argparse.ArgumentParser(description="Display scanner statistics")
    parser.add_argument('--assets', '-a', action='store_true', help='Show only asset stats')
    parser.add_argument('--findings', '-f', action='store_true', help='Show only findings stats')
    parser.add_argument('--changes', '-c', action='store_true', help='Show only change stats')
    parser.add_argument('--all', '-A', action='store_true', help='Show all stats (default)')
    
    args = parser.parse_args()
    
    # If no specific option is given, show all
    if not any([args.assets, args.findings, args.changes, args.all]):
        args.all = True
    
    if args.all:
        show_all_stats()
    else:
        if args.assets:
            show_asset_stats()
        if args.findings:
            if args.assets or args.changes:  # Add space if multiple options
                print()
            show_finding_stats()
        if args.changes:
            if args.assets or args.findings:  # Add space if multiple options
                print()
            show_change_stats()

if __name__ == "__main__":
    main()