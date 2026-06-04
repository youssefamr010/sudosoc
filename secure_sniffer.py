#!/usr/bin/env python3
"""
Auto-Deploy Secure Sniffer for SudoSOC IDS/IPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Auto-starts mitmproxy alongside the IDS engine, monitors health,
and feeds decrypted flows into the ML pipeline.

Features:
  - Daemon thread auto-start with IDS engine
  - Health watchdog (restarts mitmdump on crash)
  - Decrypted flow ingestion from JSONL
  - TLS metadata extraction (SNI, JA3 fingerprints)
  - System proxy auto-config (Windows)
"""

import subprocess
import os
import sys
import time
import json
import math
import socket
import signal
import logging
import threading
import platform
from datetime import datetime
from typing import Dict, Optional, Callable
from collections import deque

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SecureSniffer")

IS_WINDOWS = platform.system() == "Windows"


class SecureSniffer:
    """
    Manages the mitmproxy process as a daemon alongside the IDS engine.
    Includes health monitoring and auto-restart capabilities.
    """

    def __init__(self, port: int = 9090, addon_path: str = "mitm_addon.py",
                 auto_proxy: bool = False):
        self.port = port
        self.addon_path = addon_path
        self.auto_proxy = auto_proxy
        self.process = None
        self._stop_evt = threading.Event()
        self._watchdog_thread = None
        self._restart_count = 0
        self._max_restarts = 5
        self._started = False

    def start(self, blocking: bool = False):
        """
        Start mitmproxy sniffer.
        If blocking=False, runs as daemon thread (default for IDS integration).
        """
        if not self._check_mitmdump():
            logger.warning("mitmdump not found — encrypted traffic sniffing disabled.")
            if self.auto_proxy and IS_WINDOWS:
                self._set_system_proxy(False)
            return False

        if self.auto_proxy and IS_WINDOWS:
            self._set_system_proxy(True)

        if blocking:
            self._start_process()
            return True
        else:
            # Start as daemon thread
            thread = threading.Thread(target=self._start_process,
                                      daemon=True, name="SecureSniffer")
            thread.start()

            # Start watchdog
            self._watchdog_thread = threading.Thread(
                target=self._watchdog_loop, daemon=True, name="SnifferWatchdog"
            )
            self._watchdog_thread.start()
            return True

    def _check_mitmdump(self) -> bool:
        """Check if mitmdump is available."""
        import shutil
        cmd = shutil.which("mitmdump")
        if cmd:
            self._mitmdump_path = cmd
            return True
            
        # Fallback for Windows AppData scripts
        if IS_WINDOWS:
            # Common paths for Windows Store Python or Pip --user
            possible_scripts = [
                os.path.join(os.environ.get("LOCALAPPDATA", ""), "Packages", "PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0", "LocalCache", "local-packages", "Python311", "Scripts"),
                os.path.join(os.environ.get("APPDATA", ""), "Python", "Python311", "Scripts"),
                os.path.join(sys.prefix, "Scripts")
            ]
            for p in possible_scripts:
                exe = os.path.join(p, "mitmdump.exe")
                if os.path.exists(exe):
                    self._mitmdump_path = exe
                    logger.info(f"mitmdump found in fallback path: {exe}")
                    return True
        return False

    def _kill_stale_mitmdump(self):
        """Kill any orphaned mitmdump processes holding our port."""
        try:
            if IS_WINDOWS:
                # Find PIDs listening on our port and kill mitmdump ones
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines():
                    if f":{self.port}" in line and "LISTENING" in line:
                        parts = line.split()
                        pid = parts[-1]
                        try:
                            pid_int = int(pid)
                            if pid_int > 4:  # Don't kill system processes
                                subprocess.run(
                                    ["taskkill", "/PID", str(pid_int), "/F"],
                                    capture_output=True, timeout=5
                                )
                                logger.info(f"Killed stale process PID {pid_int} on port {self.port}")
                                time.sleep(1)  # Let OS release the port
                        except (ValueError, subprocess.SubprocessError):
                            pass
            else:
                subprocess.run(
                    ["fuser", "-k", f"{self.port}/tcp"],
                    capture_output=True, timeout=5
                )
                time.sleep(1)
        except Exception as e:
            logger.debug(f"Stale process cleanup: {e}")

    def _is_port_free(self) -> bool:
        """Check if the sniffer port is available."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.bind(('0.0.0.0', self.port))
                return True
        except OSError:
            return False

    def _start_process(self):
        """Start the mitmdump subprocess."""
        logger.info(f"Starting Decryption Sniffer on port {self.port}...")

        # Kill any stale mitmdump that might be holding the port
        if not self._is_port_free():
            logger.warning(f"Port {self.port} is occupied. Cleaning up stale processes...")
            self._kill_stale_mitmdump()
            time.sleep(2)  # Wait for port to be released
            if not self._is_port_free():
                logger.error(f"Port {self.port} still occupied after cleanup. Sniffer cannot start.")
                self._started = False
                return

        cmd = [getattr(self, "_mitmdump_path", "mitmdump"), 
               "-p", str(self.port), 
               "-s", self.addon_path,
               "-q"]

        try:
            self._stderr_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "mitmdump_stderr.log"
            )
            self._stderr_file = open(self._stderr_path, "w", encoding="utf-8")
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=self._stderr_file,
                shell=False
            )
            self._started = True
            logger.info(f"SecureSniffer (mitmproxy) started on port {self.port} (PID: {self.process.pid})")
        except Exception as e:
            logger.error(f"Failed to start sniffer: {e}")
            if self.auto_proxy and IS_WINDOWS:
                self._set_system_proxy(False)
            self._started = False

    def _watchdog_loop(self):
        """Monitor sniffer health and restart on crash with backoff."""
        time.sleep(5)  # Grace period for initial startup
        while not self._stop_evt.is_set():
            time.sleep(5)
            if self.process and self.process.poll() is not None:
                # Process died
                exit_code = self.process.returncode

                # Log stderr for diagnostics
                stderr_msg = ""
                try:
                    if hasattr(self, '_stderr_file') and self._stderr_file:
                        self._stderr_file.close()
                    if hasattr(self, '_stderr_path') and os.path.exists(self._stderr_path):
                        with open(self._stderr_path, "r", encoding="utf-8", errors="ignore") as f:
                            stderr_msg = f.read().strip()[-500:]  # Last 500 chars
                except Exception:
                    pass

                if self._restart_count < self._max_restarts and not self._stop_evt.is_set():
                    self._restart_count += 1
                    backoff = min(2 ** self._restart_count, 30)  # exponential backoff, max 30s
                    logger.warning(
                        f"Sniffer crashed (exit={exit_code}). "
                        f"Restarting ({self._restart_count}/{self._max_restarts}) "
                        f"after {backoff}s backoff..."
                    )
                    if stderr_msg:
                        logger.warning(f"Sniffer stderr: {stderr_msg}")
                    time.sleep(backoff)
                    self._start_process()
                elif self._restart_count >= self._max_restarts:
                    logger.error(
                        f"Sniffer exceeded max restarts — giving up. "
                        f"Last stderr: {stderr_msg}"
                    )
                    break

    def stop(self):
        """Stop sniffer and cleanup."""
        self._stop_evt.set()

        if self.auto_proxy and IS_WINDOWS:
            self._set_system_proxy(False)

        if self.process:
            logger.info("Stopping Decryption Sniffer...")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            logger.info("Sniffer stopped.")

        # Close stderr log file
        try:
            if hasattr(self, '_stderr_file') and self._stderr_file:
                self._stderr_file.close()
        except Exception:
            pass

    def _set_system_proxy(self, enable: bool):
        """Set/unset Windows system proxy to route through mitm."""
        if not IS_WINDOWS:
            return
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                0, winreg.KEY_SET_VALUE
            )
            if enable:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ,
                                  f"127.0.0.1:{self.port}")
                logger.info(f"System proxy set to 127.0.0.1:{self.port}")
            else:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                logger.info("System proxy disabled")
            winreg.CloseKey(key)
        except Exception as e:
            logger.warning(f"Could not set system proxy: {e}")

    @property
    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def get_status(self) -> Dict:
        return {
            "running": self.is_running,
            "port": self.port,
            "restarts": self._restart_count,
            "proxy_enabled": self.auto_proxy,
        }


class DecryptedFlowIngester:
    """
    Watches decrypted_flows.jsonl for new lines and feeds them
    through the ML pipeline for scoring.
    """

    def __init__(self, jsonl_path: str = "decrypted_flows.jsonl",
                 callback: Optional[Callable] = None,
                 poll_interval: float = 1.0):
        self.jsonl_path = jsonl_path
        self.callback = callback
        self.poll_interval = poll_interval
        self._stop_evt = threading.Event()
        self._file_pos = 0
        self._ingested_count = 0
        self._recent_flows = deque(maxlen=100)

    def start(self):
        """Start the ingester as a daemon thread."""
        thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="FlowIngester"
        )
        thread.start()
        logger.info(f"DecryptedFlowIngester watching: {self.jsonl_path}")

    def stop(self):
        self._stop_evt.set()

    def _poll_loop(self):
        """Tail the JSONL file for new flows."""
        # Seek to end on startup (only process new flows)
        if os.path.exists(self.jsonl_path):
            self._file_pos = os.path.getsize(self.jsonl_path)

        while not self._stop_evt.is_set():
            time.sleep(self.poll_interval)
            try:
                if not os.path.exists(self.jsonl_path):
                    continue

                current_size = os.path.getsize(self.jsonl_path)
                if current_size <= self._file_pos:
                    if current_size < self._file_pos:
                        # File was truncated/rotated
                        self._file_pos = 0
                    continue

                with open(self.jsonl_path, "r", encoding="utf-8",
                          errors="ignore") as f:
                    f.seek(self._file_pos)
                    new_lines = f.readlines()
                    self._file_pos = f.tell()

                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        flow = json.loads(line)
                        self._process_flow(flow)
                    except json.JSONDecodeError:
                        pass

            except Exception as e:
                logger.debug(f"Ingester error: {e}")

    def _process_flow(self, flow: Dict):
        """Process a single decrypted flow."""
        self._ingested_count += 1

        # Enrich with additional metadata
        flow["_source"] = "mitmproxy"
        flow["_ingested_at"] = datetime.now().isoformat()

        # Compute payload entropy if content sizes available
        req_size = flow.get("request_size", 0) or 0
        resp_size = flow.get("response_size", 0) or 0
        total_size = req_size + resp_size
        flow["bidirectional_bytes"] = total_size
        flow["bidirectional_packets"] = max(1, total_size // 1460 + 1)  # estimate
        flow["bidirectional_duration_ms"] = 0  # not available from MITM

        # Extract TLS metadata
        flow["tls_sni"] = flow.get("sni", "")
        flow["tls_host"] = flow.get("host", "")

        self._recent_flows.append(flow)

        if self.callback:
            self.callback(flow)

    def get_stats(self) -> Dict:
        return {
            "ingested_count": self._ingested_count,
            "recent_flows": len(self._recent_flows),
            "watching": self.jsonl_path,
        }


# ── CLI ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if "--check" in sys.argv:
        sniffer = SecureSniffer()
        if sniffer._check_mitmdump():
            print("[OK] mitmdump is available")
        else:
            print("[ERR] mitmdump not found — pip install mitmproxy")
        sys.exit(0)

    sniffer = SecureSniffer()
    try:
        sniffer.start(blocking=True)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sniffer.stop()
