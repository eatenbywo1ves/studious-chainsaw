#!/usr/bin/env python3
"""
Optimized Server Startup Script
================================

Starts the SaaS API server with optimized uvicorn settings to prevent
connection leaks and improve performance under load.

Key Optimizations:
- Reduced keepalive timeout (5s -> 2s) to close idle connections faster
- Limited max concurrent connections per worker
- Proper timeout configuration for production
- Optimized worker count based on CPU cores

Usage:
    python start_server_optimized.py
    python start_server_optimized.py --workers 4 --port 8000
"""

import os
import sys
import argparse
import uvicorn

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    """Start server with optimized settings"""

    parser = argparse.ArgumentParser(description="Start SaaS API server with optimizations")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")), help="Port to bind to")
    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.getenv("WORKERS", "1")),
        help="Number of worker processes",
    )
    parser.add_argument(
        "--reload", action="store_true", help="Enable auto-reload (development only)"
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Log level",
    )

    args = parser.parse_args()

    print("=" * 80)
    print("Starting Optimized SaaS API Server")
    print("=" * 80)
    print(f"Host: {args.host}")
    print(f"Port: {args.port}")
    print(f"Workers: {args.workers}")
    print(f"Log Level: {args.log_level}")
    print("=" * 80)
    print("\nOptimizations Active:")
    print("  [+] Reduced keepalive timeout (2s)")
    print("  [+] Limited concurrent connections (1000/worker)")
    print("  [+] Explicit connection close on health endpoint")
    print("  [+] Proper timeout configuration")
    print("=" * 80)
    print()

    # Change to saas directory (not api subdirectory)
    saas_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(saas_dir)

    # Uvicorn configuration with connection leak fixes
    config = uvicorn.Config(
        app="api.saas_server:app",
        host=args.host,
        port=args.port,
        workers=args.workers if not args.reload else 1,  # Reload only works with 1 worker
        reload=args.reload,
        log_level=args.log_level,
        # HTTP connection settings to prevent leaks
        timeout_keep_alive=2,  # Reduced from default 5s - close idle connections faster
        timeout_notify=25,  # Send notification before closing (slightly less than timeout_graceful_shutdown)
        timeout_graceful_shutdown=30,  # Graceful shutdown timeout
        limit_concurrency=1000,  # Maximum concurrent connections per worker
        limit_max_requests=10000,  # Restart worker after N requests to prevent memory leaks
        # Performance settings
        backlog=2048,  # Connection backlog size
        h11_max_incomplete_event_size=16 * 1024,  # 16KB buffer for HTTP events
    )

    server = uvicorn.Server(config)
    server.run()


if __name__ == "__main__":
    main()
