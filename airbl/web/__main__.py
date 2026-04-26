"""
Entry point for running the web server as a module.

Usage: python -m airbl.web
"""

import asyncio
import os
import sys
from pathlib import Path
from .app import run_server

def main():
    """Main entry point."""
    # Read from environment variables (set by Docker)
    config_dir = Path(os.getenv("AIRBL_CONFIG_DIR", "/app/conf"))
    port = int(os.getenv("PORT", "5665"))
    interval = int(os.getenv("SCAN_INTERVAL", "120"))
    auto_scan = os.getenv("AUTO_SCAN", "true").lower() == "true"
    host = os.getenv("HOST", "0.0.0.0")
    
    # Parse command line args (override env vars)
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
            i += 2
        elif arg == "--host" and i + 1 < len(sys.argv):
            host = sys.argv[i + 1]
            i += 2
        elif arg == "--config-dir" and i + 1 < len(sys.argv):
            config_dir = Path(sys.argv[i + 1])
            i += 2
        elif arg == "--interval" and i + 1 < len(sys.argv):
            interval = int(sys.argv[i + 1])
            i += 2
        elif arg == "--no-auto-scan":
            auto_scan = False
            i += 1
        elif arg == "--auto-scan":
            auto_scan = True
            i += 1
        else:
            i += 1
    
    print(f"Starting AirBL web server on {host}:{port}")
    print(f"Config directory: {config_dir}")
    print(f"Scan interval: {interval} minutes")
    print(f"Auto-scan: {auto_scan}")
    
    asyncio.run(run_server(
        host=host,
        port=port,
        config_dir=config_dir,
        scan_interval_minutes=interval,
        auto_scan=auto_scan,
    ))

if __name__ == "__main__":
    main()

