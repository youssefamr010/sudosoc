import os
import sys
import webbrowser
import time
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
import threading

PORT = 8080

def start_server():
    TCPServer.allow_reuse_address = True
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Silence terminal print noise from standard HTTP requests to keep output clean
    class QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

    with TCPServer(("", PORT), QuietHandler) as httpd:
        print(f"[SUCCESS] SudoSOC Local HTTP Server active on http://localhost:{PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    print("=" * 64)
    print("           SUDOSOC — SECURITY OPERATIONS CENTER CONSOLE")
    print("=" * 64)
    print("Initializing local HTTP environment...")
    
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # Wait a brief moment for binding
    time.sleep(0.5)
    
    # Open the browser to the original multi-file modular console
    url = f"http://localhost:{PORT}/SudoSOC Design System/ui_kits/console/index.html"
    print(f"\n[INFO] Opening your default web browser to the console:")
    print(f"       -> {url}")
    webbrowser.open(url)
    
    print("\n[ACTIVE] Local console server is running.")
    print("         -> Keep this window open while using the dashboard.")
    print("         -> Press Ctrl+C in this terminal window to stop the server.")
    print("=" * 64)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] SudoSOC console server stopped successfully.")
        sys.exit(0)
