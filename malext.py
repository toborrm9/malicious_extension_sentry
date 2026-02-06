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
from pathlib import Path

# Database URL
CSV_URL = "https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/refs/heads/main/Malicious-Extensions.csv"

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
    """Get browser paths based on OS"""
    os_name = platform.system()
    paths = []
    
    if os_name == "Darwin":  # macOS
        paths = [
            ("Chrome", Path.home() / "Library/Application Support/Google/Chrome"),
            ("Edge", Path.home() / "Library/Application Support/Microsoft Edge"),
        ]
    elif os_name == "Windows":
        paths = [
            ("Chrome", Path.home() / "AppData/Local/Google/Chrome/User Data"),
            ("Edge", Path.home() / "AppData/Local/Microsoft/Edge/User Data"),
        ]
    elif os_name == "Linux":
        paths = [
            ("Chrome", Path.home() / ".config/google-chrome"),
            ("Edge", Path.home() / ".config/microsoft-edge"),
            ("Chromium", Path.home() / ".config/chromium"),
        ]
    
    return paths

def download_database():
    """Download malicious extensions list"""
    print("📥 Downloading latest malicious extensions database...")
    try:
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(CSV_URL, timeout=10, context=ctx) as r:
            content = r.read().decode('utf-8')
        ids = {x.strip() for x in content.replace('\n', ',').split(',') if x.strip()}
        print(f"✅ Loaded {len(ids)} known malicious extension IDs\n")
        return ids
    except Exception as e:
        print(f"❌ Error: {e}\n")
        return set()

def get_extensions():
    """Get all installed extensions"""
    extensions = []
    browsers = get_browser_paths()
    
    for browser, path in browsers:
        if not path.exists():
            continue
        for profile in path.iterdir():
            if profile.name in ["Default"] or profile.name.startswith("Profile"):
                ext_path = profile / "Extensions"
                if ext_path.exists():
                    for ext in ext_path.iterdir():
                        if ext.is_dir():
                            name = get_name(ext)
                            extensions.append({
                                'id': ext.name,
                                'name': name,
                                'browser': browser,
                                'profile': profile.name
                            })
    return extensions

def get_name(ext_path):
    """Get extension name from manifest"""
    try:
        versions = [f for f in ext_path.iterdir() if f.is_dir()]
        if versions:
            manifest = sorted(versions)[-1] / "manifest.json"
            if manifest.exists():
                with open(manifest, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    name = data.get('name', 'Unknown')
                    return name if not name.startswith('__MSG_') else data.get('short_name', 'Unknown')
    except:
        pass
    return "Unknown"

def main():
    """Main function"""
    banner()
    time.sleep(1.5)
    
    # Detect OS platform
    os_name = platform.system()
    os_display = {"Darwin": "macOS", "Windows": "Windows", "Linux": "Linux"}.get(os_name, os_name)
    print(f"💻 Detected OS: {os_display}\n")
    
    # Get database
    malicious = download_database()
    if not malicious:
        return
    
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
        browser_counts[e['browser']] = browser_counts.get(e['browser'], 0) + 1
    
    count_str = ", ".join([f"{b}: {c}" for b, c in browser_counts.items()])
    print(f"✅ Found {len(extensions)} extensions ({count_str})\n")
    
    # Check for matches
    threats = [e for e in extensions if e['id'] in malicious]
    
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
    
    print("=" * 70)
    print(f"📊 Database: {len(malicious)} known malicious extensions")
    print(f"🌐 Source: {CSV_URL}")
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