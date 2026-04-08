"""
server.py — Root-level entry point for backwards compatibility.
The canonical server is defined in server/app.py.
"""
from server.app import app, main

__all__ = ["app"]

if __name__ == "__main__":
    main()
