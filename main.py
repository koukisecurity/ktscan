#!/usr/bin/env python3
"""
Certificate Scanner - Entry Point

A multithreaded tool for scanning SSL/TLS certificates.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ktscan.cli import main

if __name__ == '__main__':
    main()