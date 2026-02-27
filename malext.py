#!/usr/bin/env python3
"""
MalExt - Malicious Extension Scanner
Cross-platform tool to check your browser extensions for known threats
Supports: Windows, macOS, Linux
"""

import json
import ssl
import time
import urllib.request
import platform
import os
from pathlib import Path

# Database URLs
CSV_URL = "https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/refs/heads/main/Malicious-Extensions.csv"
# TODO: Update SPY_CSV_URL to the upstream repository owner's URL before merging/publishing
SPY_CSV_URL = "https://raw.githubusercontent.com/gembleman/malicious_extension_sentry/refs/heads/feature/spy-extensions-detection/Spy-Extensions.csv"


def banner():
    """Display banner"""
    print("\n╔════════════════════════════════════════════════════════════════════╗")
    print("║        ███╗   ███╗ █████╗ ██╗     ███████╗██╗  ██╗████████╗      ║")
    print("║        ████╗ ████║██╔══██╗██║     ██╔════╝╚██╗██╔╝╚══██╔══╝      ║")
    print("║        ██╔████╔██║███████║██║     █████╗   ╚███╔╝    ██║         ║")
    print("║        ██║╚██╔╝██║██╔══██║██║     ██╔══╝   ██╔██╗    ██║         ║")
    print("║        ██║ ╚═╝ ██║██║  ██║███████╗███████╗██╔╝ ██╗   ██║         ║")
    print("║        ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝         ║")
    print("║              🛡️  Malicious Extension Scanner v1.0 🛡️              ║")
    print("║                    Created by: @toborrm9                          ║")
    print("║         GitHub: github.com/toborrm9/malicious_extension_sentry    ║")
    print("╚════════════════════════════════════════════════════════════════════╝\n")


def get_browser_paths():
    """Get browser paths based on OS (known + discovered Chromium-style data dirs)"""
    os_name = platform.system()
    paths = []
    seen = set()
    local_app_data = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    roaming_app_data = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))

    if os_name == "Darwin":  # macOS
        paths = [
            ("Chrome", Path.home() / "Library/Application Support/Google/Chrome"),
            ("Edge", Path.home() / "Library/Application Support/Microsoft Edge"),
            (
                "Brave",
                Path.home() / "Library/Application Support/BraveSoftware/Brave-Browser",
            ),
            ("Chromium", Path.home() / "Library/Application Support/Chromium"),
            ("Vivaldi", Path.home() / "Library/Application Support/Vivaldi"),
            (
                "Opera",
                Path.home() / "Library/Application Support/com.operasoftware.Opera",
            ),
            ("Arc", Path.home() / "Library/Application Support/Arc/User Data"),
            ("Thorium", Path.home() / "Library/Application Support/Thorium/User Data"),
            ("Helium", Path.home() / "Library/Application Support/Helium/User Data"),
        ]
    elif os_name == "Windows":
        paths = [
            ("Chrome", local_app_data / "Google/Chrome/User Data"),
            ("Edge", local_app_data / "Microsoft/Edge/User Data"),
            ("Brave", local_app_data / "BraveSoftware/Brave-Browser/User Data"),
            ("Chromium", local_app_data / "Chromium/User Data"),
            ("Vivaldi", local_app_data / "Vivaldi/User Data"),
            ("Opera", roaming_app_data / "Opera Software/Opera Stable"),
            ("Opera GX", roaming_app_data / "Opera Software/Opera GX Stable"),
            ("Arc", local_app_data / "Arc/User Data"),
            ("Thorium", local_app_data / "Thorium/User Data"),
            ("Helium", local_app_data / "Helium/User Data"),
            ("Comodo Dragon", local_app_data / "Comodo/Dragon/User Data"),
            (
                "Avast Secure Browser",
                local_app_data / "AVAST Software/Browser/User Data",
            ),
            ("AVG Secure Browser", local_app_data / "AVG/Browser/User Data"),
        ]
    elif os_name == "Linux":
        paths = [
            ("Chrome", Path.home() / ".config/google-chrome"),
            ("Edge", Path.home() / ".config/microsoft-edge"),
            ("Chromium", Path.home() / ".config/chromium"),
            ("Brave", Path.home() / ".config/BraveSoftware/Brave-Browser"),
            ("Vivaldi", Path.home() / ".config/vivaldi"),
            ("Opera", Path.home() / ".config/opera"),
            ("Thorium", Path.home() / ".config/thorium"),
            ("Arc", Path.home() / ".config/arc"),
            ("Helium", Path.home() / ".config/helium"),
            ("Comodo Dragon", Path.home() / ".config/comodo-dragon"),
            ("Avast Secure Browser", Path.home() / ".config/avast-browser"),
        ]

    discovered = discover_browser_paths(os_name, local_app_data, roaming_app_data)

    combined = []
    for browser, path in paths + discovered:
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        combined.append((browser, path))

    return combined


def discover_browser_paths(os_name, local_app_data, roaming_app_data):
    """Discover Chromium-style browser data dirs so less common browsers are included"""
    roots = []
    if os_name == "Windows":
        roots = [local_app_data, roaming_app_data]
    elif os_name == "Darwin":
        roots = [Path.home() / "Library/Application Support"]
    elif os_name == "Linux":
        roots = [Path.home() / ".config", Path.home() / ".var/app"]

    discovered = []
    seen = set()

    for root in roots:
        if not root.exists():
            continue
        for data_dir in find_data_dirs(root):
            if not has_extensions_structure(data_dir):
                continue
            key = str(data_dir).lower()
            if key in seen:
                continue
            seen.add(key)
            discovered.append((infer_browser_name(data_dir), data_dir))

    return discovered


def find_data_dirs(root):
    """Return likely Chromium data directories under a root"""
    matches = []
    max_depth = 4
    stack = [(root, 0)]

    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            continue
        try:
            children = [p for p in current.iterdir() if p.is_dir()]
        except Exception:
            continue

        name_lower = current.name.lower()
        if name_lower == "user data" or "opera" in name_lower:
            matches.append(current)
            continue

        for child in children:
            stack.append((child, depth + 1))

    return matches


def has_extensions_structure(data_dir):
    """Check if directory looks like a Chromium profile root"""
    if (data_dir / "Extensions").exists():
        return True

    for name in ("Default", "Profile 1", "Profile 2"):
        if (data_dir / name / "Extensions").exists():
            return True
    return False


def infer_browser_name(path):
    """Infer browser name from path for dynamically discovered directories"""
    parts = [p.lower() for p in path.parts]
    tokens = {
        "brave-browser": "Brave",
        "bravesoftware": "Brave",
        "vivaldi": "Vivaldi",
        "microsoft edge": "Edge",
        "edge": "Edge",
        "chrome": "Chrome",
        "chromium": "Chromium",
        "arc": "Arc",
        "thorium": "Thorium",
        "helium": "Helium",
        "dragon": "Comodo Dragon",
        "comodo": "Comodo Dragon",
        "avast software": "Avast Secure Browser",
        "avast": "Avast Secure Browser",
        "avg": "AVG Secure Browser",
        "opera gx stable": "Opera GX",
        "opera stable": "Opera",
        "com.operasoftware.opera": "Opera",
        "opera": "Opera",
    }

    for part in reversed(parts):
        if part in tokens:
            return tokens[part]

    if path.name.lower() == "user data":
        return path.parent.name
    return path.name


def download_database():
    """Download malicious extensions list"""
    print("📥 Downloading latest malicious extensions database...")
    try:
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(CSV_URL, timeout=10, context=ctx) as r:
            content = r.read().decode("utf-8")
        ids = {x.strip() for x in content.replace("\n", ",").split(",") if x.strip()}
        print(f"✅ Loaded {len(ids)} known malicious extension IDs\n")
        return ids
    except Exception as e:
        print(f"❌ Error: {e}\n")
        return set()


def download_spy_database():
    """Download spying extensions list (qcontinuum1/spying-extensions IoCs).
    Falls back to local Spy-Extensions.csv if network is unavailable."""
    local_csv = Path(__file__).parent / "Spy-Extensions.csv"

    def parse_csv(content):
        """Parse extension_id,name,source,insert_date_fmt CSV."""
        result = {}
        lines = content.splitlines()
        for line in lines[1:]:  # skip header
            parts = line.split(",", 3)
            if len(parts) >= 2:
                ext_id = parts[0].strip()
                name = parts[1].strip()
                if len(ext_id) == 32:
                    result[ext_id] = name
        return result

    print("📥 Downloading latest spying extensions database...")
    try:
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(SPY_CSV_URL, timeout=10, context=ctx) as r:
            content = r.read().decode("utf-8")
        data = parse_csv(content)
        print(f"✅ Loaded {len(data)} known spying extension IDs\n")
        return data
    except Exception:
        pass

    if local_csv.exists():
        try:
            with open(local_csv, encoding="utf-8") as f:
                content = f.read()
            data = parse_csv(content)
            print(f"✅ Loaded {len(data)} known spying extension IDs (local cache)\n")
            return data
        except Exception as e:
            print(f"❌ Failed to load local spy database: {e}\n")

    print("⚠️  Could not load spying extensions database (skipping)\n")
    return {}


def get_extensions():
    """Get all installed extensions"""
    extensions = []
    browsers = get_browser_paths()

    for browser, path in browsers:
        if not path.exists():
            continue
        for profile in get_profile_dirs(path):
            ext_path = profile / "Extensions"
            if ext_path.exists():
                for ext in ext_path.iterdir():
                    if ext.is_dir():
                        name = get_name(ext)
                        extensions.append(
                            {
                                "id": ext.name,
                                "name": name,
                                "browser": browser,
                                "profile": profile.name,
                            }
                        )

    return extensions


def get_profile_dirs(browser_path):
    """Return profile directories for a browser data path"""
    if (browser_path / "Extensions").exists():
        return [browser_path]

    profiles = []
    for item in browser_path.iterdir():
        if item.is_dir() and (
            item.name == "Default" or item.name.startswith("Profile")
        ):
            profiles.append(item)
    return profiles


def get_name(ext_path):
    """Get extension name from manifest"""
    try:
        versions = [f for f in ext_path.iterdir() if f.is_dir()]
        if versions:
            manifest = sorted(versions)[-1] / "manifest.json"
            if manifest.exists():
                with open(manifest, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    name = data.get("name", "Unknown")
                    return (
                        name
                        if not name.startswith("__MSG_")
                        else data.get("short_name", "Unknown")
                    )
    except:
        pass
    return "Unknown"


def main():
    """Main function"""
    banner()
    time.sleep(1.5)

    # Detect OS platform
    os_name = platform.system()
    os_display = {"Darwin": "macOS", "Windows": "Windows", "Linux": "Linux"}.get(
        os_name, os_name
    )
    print(f"💻 Detected OS: {os_display}\n")

    # Get databases
    malicious = download_database()
    if not malicious:
        return
    spying = download_spy_database()

    # Scan extensions
    print("🔎 Scanning installed extensions...")
    extensions = get_extensions()

    if not extensions:
        print(f"❌ No extensions found")
        print(f"   Make sure Chrome or Edge is installed on {os_display}\n")
        return

    # Count by browser
    browser_counts = {}
    for e in extensions:
        browser_counts[e["browser"]] = browser_counts.get(e["browser"], 0) + 1

    count_str = ", ".join([f"{b}: {c}" for b, c in browser_counts.items()])
    print(f"✅ Found {len(extensions)} extensions ({count_str})\n")

    # Check for matches
    threats = [e for e in extensions if e["id"] in malicious]

    print("=" * 70)
    print("📊 SCAN RESULTS")
    print("=" * 70 + "\n")

    if threats:
        print(f"⚠️  WARNING: {len(threats)} MALICIOUS EXTENSION(S) DETECTED!\n")
        print("🔴 REMOVE THESE IMMEDIATELY:")
        print("-" * 70)
        for t in threats:
            print(f"❌ {t['name']}")
            print(f"   ID: {t['id']}")
            print(f"   Browser: {t['browser']} ({t['profile']})")
            print(f"   URL: https://chromewebstore.google.com/detail/{t['id']}\n")

        # OS-specific removal instructions
        if os_name == "Windows":
            print("🛡️  HOW TO REMOVE (Windows):")
            print(f"   1. Open {threats[0]['browser']}")
            print("   2. Type: chrome://extensions in address bar")
            print("   3. Find the extension and click 'Remove'\n")
        elif os_name == "Darwin":
            print("🛡️  HOW TO REMOVE (macOS):")
            print(f"   1. Open {threats[0]['browser']}")
            print("   2. Go to Extensions (⋮ menu → Extensions → Manage Extensions)")
            print("   3. Find the extension and click 'Remove'\n")
        else:
            print("🛡️  HOW TO REMOVE (Linux):")
            print(f"   1. Open {threats[0]['browser']}")
            print("   2. Type: chrome://extensions in address bar")
            print("   3. Find the extension and click 'Remove'\n")
    else:
        print(f"✅ GOOD NEWS: No malicious extensions detected!\n")
        print(f"   All {len(extensions)} extensions are clear.\n")

    # Check for spying extension matches
    if spying:
        spies = [e for e in extensions if e["id"] in spying]
        print("=" * 70)
        print("🕵️  SPY EXTENSION SCAN RESULTS (qcontinuum1/spying-extensions)")
        print("=" * 70 + "\n")

        if spies:
            print(f"⚠️  WARNING: {len(spies)} SPYING EXTENSION(S) DETECTED!\n")
            print("🟡 THESE EXTENSIONS EXFILTRATE YOUR BROWSING HISTORY:")
            print("-" * 70)
            for t in spies:
                ioc_name = spying.get(t["id"], t["name"])
                print(f"👁️  {ioc_name}")
                print(f"   ID: {t['id']}")
                print(f"   Browser: {t['browser']} ({t['profile']})")
                print(f"   URL: https://chromewebstore.google.com/detail/{t['id']}\n")
        else:
            print(f"✅ GOOD NEWS: No spying extensions detected!\n")
            print(f"   All {len(extensions)} extensions are clear.\n")

    print("=" * 70)
    print(f"📊 Malicious DB: {len(malicious)} extensions | Spy DB: {len(spying)} extensions")
    print(f"🌐 Sources:")
    print(f"   Malicious: {CSV_URL}")
    print(f"   Spying:    {SPY_CSV_URL}")
    print("=" * 70 + "\n")
    print("🙏 Star the repo: github.com/toborrm9/malicious_extension_sentry")
    print("🐛 Report threats: Open an issue on GitHub!\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan cancelled\n")
    except Exception as e:
        print(f"\n❌ Error: {e}\n")
