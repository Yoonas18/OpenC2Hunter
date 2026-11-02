import re
from pathlib import Path

import psutil

# Common C2 & Suspicious Keyword Signatures
SUSPICIOUS_KEYWORDS = {
    "c2", "beacon", "powershell", "cmd.exe", "whoami", "rundll32",
    "mimikatz", "sliver", "cobalt", "meterpreter", "reverse_tcp",
    "virtualalloc", "writeprocessmemory", "createremotethread",
    "downloadstring", "invoke-expression", "iex", "certutil",
    "bitsadmin", "wscript", "cscript", "regsvr32", "schtasks"
}

URL_REGEX = re.compile(r"https?://[a-zA-Z0-9.-]+(?::[0-9]+)?(?:/[^\s\"'<>\\()]+)?")
IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
BASE64_REGEX = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")

def extract_strings_from_bytes(data: bytes, min_len: int = 4) -> list[str]:
    """Extracts printable ASCII and UTF-16LE strings from a byte stream."""
    strings = []
    # ASCII strings
    ascii_pat = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    for match in ascii_pat.finditer(data):
        try:
            strings.append(match.group().decode("ascii"))
        except Exception:
            pass

    # UTF-16LE strings (common in Windows binaries and payloads)
    utf16_pat = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}")
    for match in utf16_pat.finditer(data):
        try:
            strings.append(match.group().decode("utf-16le"))
        except Exception:
            pass

    return strings

def inspect_process_memory_and_binary(pid: int) -> dict:
    """
    Inspects accessible binary and memory strings of a running process PID,
    extracting embedded URLs, remote IPs, suspicious C2 commands, and cryptographic markers.
    """
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        exe_path = proc.exe() or "N/A"
        cmdline = " ".join(proc.cmdline()) if proc.cmdline() else "N/A"
        username = proc.username() if hasattr(proc, "username") else "N/A"
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return {"error": f"Cannot access PID {pid}: {e}", "pid": pid}

    raw_bytes = bytearray()

    # 1. Read executable file from disk if accessible
    if exe_path and exe_path != "N/A" and Path(exe_path).exists():
        try:
            with open(exe_path, "rb") as f:
                # Read first 1MB of the binary
                raw_bytes.extend(f.read(1024 * 1024))
        except Exception:
            pass

    # 2. Append commandline bytes
    raw_bytes.extend(cmdline.encode("utf-8", errors="ignore"))

    all_strings = extract_strings_from_bytes(bytes(raw_bytes), min_len=4)

    discovered_urls = set()
    discovered_ips = set()
    c2_indicators = []
    base64_blobs = []

    for s in all_strings:
        s_lower = s.lower()

        # URLs
        for url in URL_REGEX.findall(s):
            if not any(k in url.lower() for k in ["schemas.microsoft.com", "w3.org"]):
                discovered_urls.add(url)

        # IPs
        for ip in IP_REGEX.findall(s):
            if not ip.startswith(("0.", "127.", "255.")):
                discovered_ips.add(ip)

        # C2 / Attack Keywords
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in s_lower and s not in c2_indicators:
                c2_indicators.append(s[:100])
                break

        # Base64 Blobs
        if len(s) >= 40:
            for b64 in BASE64_REGEX.findall(s):
                if len(b64) >= 48 and b64 not in base64_blobs:
                    base64_blobs.append(b64[:80] + "...")

    return {
        "status": "success",
        "pid": pid,
        "process_name": proc_name,
        "exe_path": exe_path,
        "cmdline": cmdline,
        "username": username,
        "strings_extracted_count": len(all_strings),
        "discovered_urls": list(discovered_urls)[:20],
        "discovered_ips": list(discovered_ips)[:20],
        "c2_indicators": c2_indicators[:25],
        "suspicious_blobs": base64_blobs[:10],
        "sample_strings": all_strings[:50]
    }
