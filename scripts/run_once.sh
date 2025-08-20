#!/bin/bash
cd "$(dirname "$0")/.."
source venv/bin/activate
python scanner.py --domains domains.txt --once