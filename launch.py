#!/usr/bin/env python3
import os
import sys
import time
import ctypes
import secrets
import platform
import subprocess
import webbrowser
from pathlib import Path

ROOT_DIR = Path(__file__).parent.resolve()
BACKEND_DIR = ROOT_DIR / "backend"
FRONTEND_DIR = ROOT_DIR / "frontend"
DB_PATH = BACKEND_DIR / "telemetry.db"

def is_admin() -> bool:
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False

def main():
    os_name = platform.system()
    elevated = is_admin()
    enable_canaries = "--enable-canaries" in sys.argv

    session_token = secrets.token_urlsafe(32)
    env = os.environ.copy()
    env["OPENC2_SESSION_TOKEN"] = session_token
    env["VITE_OPENC2_TOKEN"] = session_token
    env["DB_PATH"] = str(DB_PATH)
    env["ENABLE_CANARIES"] = "true" if enable_canaries else "false"

    admin_user = env.get("ADMIN_USERNAME", "superadmin")
    admin_pass = env.get("ADMIN_PASSWORD", "OpenC2Hunter@2026!")

    print("=" * 72)
    print(f" OpenC2Hunter | OS: {os_name} | Admin/Root: {'YES' if elevated else 'NO (Socket Fallback)'}")
    print(f" Bind Address : 127.0.0.1:8000 (Localhost-Only CSRF Protected)")
    print(f" Canary Traps : {'ENABLED' if enable_canaries else 'DISABLED (Pass --enable-canaries to opt in)'}")
    print(f" Lab Portal   : http://127.0.0.1:3000")
    print(f" Credentials  : User: {admin_user} | Pass: {admin_pass} (Change in .env)")
    print("=" * 72)

    processes = []
    try:
        api_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend_engine:app", "--host", "127.0.0.1", "--port", "8000"],
            cwd=str(BACKEND_DIR),
            env=env
        )
        processes.append(api_proc)

        if elevated:
            sniffer_proc = subprocess.Popen(
                [sys.executable, "sniffer_daemon.py"],
                cwd=str(BACKEND_DIR),
                env=env
            )
            processes.append(sniffer_proc)

        if (FRONTEND_DIR / "package.json").exists():
            npm_cmd = "npm.cmd" if os_name == "Windows" else "npm"
            ui_proc = subprocess.Popen(
                [npm_cmd, "run", "dev", "--", "--host", "127.0.0.1", "--port", "3000"],
                cwd=str(FRONTEND_DIR),
                env=env
            )
            processes.append(ui_proc)

        time.sleep(2.5)
        webbrowser.open("http://127.0.0.1:3000")
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopping OpenC2Hunter...")
        for p in processes:
            p.terminate()
        sys.exit(0)

if __name__ == "__main__":
    main()
