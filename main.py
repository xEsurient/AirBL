#!/usr/bin/env python3
"""
AirBL - AirVPN DroneBL Checker

Thin wrapper so `python main.py ...` keeps working (Docker, entrypoint);
the CLI lives in airbl/cli.py (installed as the `airbl` console script).
"""

from airbl.cli import main

if __name__ == "__main__":
    main()
