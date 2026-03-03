#!/usr/bin/env python3
"""
MalExt - Extension Scanner (Dual Table Layout)
Malicious Table First + Clean Table Below
"""

from flask import Flask, render_template_string
import platform
import ssl
import urllib.request
import json
import os
from pathlib import Path
import webbrowser

app = Flask(__name__)

CSV_URL = "https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/refs/heads/main/Malicious-Extensions.csv"


# ==========================================================
# DOWNLOAD MALICIOUS DATABASE (LOCAL + REMOTE SUPPORT)
# ==========================================================

def download_database():
    try:
        if os.path.exists(CSV_URL):
            with open(CSV_URL, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(CSV_URL, timeout=10, context=ctx) as r:
                content = r.read().decode("utf-8")

        return {x.strip() for x in content.replace("\n", ",").split(",") if x.strip()}
    except:
        return set()


# ==========================================================
# BROWSER PATHS
# ==========================================================

def get_browser_paths():
    os_name = platform.system()
    local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    roaming = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))

    if os_name == "Windows":
        return [
            ("Chrome", local / "Google/Chrome/User Data"),
            ("Edge", local / "Microsoft/Edge/User Data"),
            ("Brave", local / "BraveSoftware/Brave-Browser/User Data"),
        ]
    elif os_name == "Darwin":
        return [
            ("Chrome", Path.home() / "Library/Application Support/Google/Chrome"),
            ("Edge", Path.home() / "Library/Application Support/Microsoft Edge"),
        ]
    elif os_name == "Linux":
        return [
            ("Chrome", Path.home() / ".config/google-chrome"),
            ("Edge", Path.home() / ".config/microsoft-edge"),
        ]
    return []


# ==========================================================
# PROFILE DISCOVERY
# ==========================================================

def get_profile_dirs(browser_path):
    profiles = []
    try:
        for item in browser_path.iterdir():
            if item.is_dir() and (
                item.name == "Default" or item.name.startswith("Profile")
            ):
                profiles.append(item)
    except:
        pass
    return profiles


# ==========================================================
# EXTENSION STATUS
# ==========================================================

def get_extension_states(profile_path):
    states = {}
    files_to_check = [
        profile_path / "Secure Preferences",
        profile_path / "Preferences"
    ]

    for prefs_file in files_to_check:
        if not prefs_file.exists():
            continue

        try:
            with open(prefs_file, "r", encoding="utf-8") as f:
                prefs = json.load(f)

            ext_settings = prefs.get("extensions", {}).get("settings", {})

            for ext_id, data in ext_settings.items():
                state = data.get("state", 1)
                disable_reasons = data.get("disable_reasons", 0)

                if state != 1:
                    states[ext_id] = "Disabled"
                elif disable_reasons and disable_reasons != 0:
                    states[ext_id] = "Disabled"
                else:
                    states[ext_id] = "Enabled"
        except:
            continue

    return states


# ==========================================================
# EXTENSION NAME (CASE-INSENSITIVE LOCALIZATION)
# ==========================================================

def get_extension_name(ext_path):
    try:
        versions = [v for v in ext_path.iterdir() if v.is_dir()]
        if not versions:
            return "Unknown"

        latest = sorted(versions)[-1]
        manifest_path = latest / "manifest.json"

        if not manifest_path.exists():
            return "Unknown"

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        name = manifest.get("name", "Unknown")

        if not name.startswith("__MSG_"):
            return name

        key = name.replace("__MSG_", "").replace("__", "").lower()
        locales = latest / "_locales"

        if not locales.exists():
            return "Localized"

        for locale_dir in locales.iterdir():
            msg_file = locale_dir / "messages.json"
            if msg_file.exists():
                with open(msg_file, "r", encoding="utf-8") as f:
                    messages = json.load(f)

                messages_lower = {k.lower(): v for k, v in messages.items()}
                if key in messages_lower:
                    return messages_lower[key].get("message", "Localized")

        return "Localized"
    except:
        return "Unknown"


# ==========================================================
# EXTENSION ENUMERATION
# ==========================================================

def get_extensions():
    extensions = []

    for browser, path in get_browser_paths():
        if not path.exists():
            continue

        for profile in get_profile_dirs(path):
            states = get_extension_states(profile)
            ext_path = profile / "Extensions"

            if ext_path.exists():
                for ext in ext_path.iterdir():
                    if ext.is_dir() and ext.name.lower() != "temp":
                        extensions.append({
                            "id": ext.name,
                            "name": get_extension_name(ext),
                            "browser": browser,
                            "profile": profile.name,
                            "status": states.get(ext.name, "Unknown")
                        })

    return extensions


# ==========================================================
# HTML TEMPLATES
# ==========================================================

HOME_TEMPLATE = """<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MalExt — Browser Extension Scanner</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
    <style>
        /* ===== DARK THEME (default) — cyan accent ===== */
        [data-theme="dark"] {
            --accent: #00f5d4;
            --accent-dim: rgba(0,245,212,0.12);
            --accent-glow: rgba(0,245,212,0.35);
            --accent-border: rgba(0,245,212,0.25);
            --red: #ff2d2d;
            --red-dim: rgba(255,45,45,0.12);
            --red-glow: rgba(255,45,45,0.35);
            --bg: #07090f;
            --bg-vignette: #07090f;
            --surface: #0d1117;
            --surface2: #131920;
            --border: rgba(255,255,255,0.07);
            --text: #e2e8f0;
            --text-inv: #07090f;
            --muted: #4a5568;
            --grid-color: rgba(0,245,212,0.025);
            --shield-stroke: #00f5d4;
            --shield-fill: rgba(0,245,212,0.07);
            --orbit-color: rgba(0,245,212,0.2);
            --topbar: linear-gradient(90deg, transparent, #00f5d4, #ff2d2d, transparent);
            --btn-border: var(--accent);
            --btn-bg: var(--accent);
            --btn-text: var(--text-inv);
            --os-bg: var(--surface2);
            --ticker-bg: var(--surface);
        }

        /* ===== LIGHT THEME — clean white with red accent ===== */
        [data-theme="light"] {
            --accent: #e63030;
            --accent-dim: rgba(230,48,48,0.08);
            --accent-glow: rgba(230,48,48,0.25);
            --accent-border: rgba(230,48,48,0.3);
            --red: #e63030;
            --red-dim: rgba(230,48,48,0.08);
            --red-glow: rgba(230,48,48,0.25);
            --bg: #f7f8fc;
            --bg-vignette: #f7f8fc;
            --surface: #ffffff;
            --surface2: #f0f2f7;
            --border: rgba(0,0,0,0.08);
            --text: #111827;
            --text-inv: #ffffff;
            --muted: #9ca3af;
            --grid-color: rgba(0,0,0,0.04);
            --shield-stroke: #e63030;
            --shield-fill: rgba(230,48,48,0.07);
            --orbit-color: rgba(230,48,48,0.18);
            --topbar: linear-gradient(90deg, transparent, #e63030, #6366f1, transparent);
            --btn-border: var(--accent);
            --btn-bg: var(--accent);
            --btn-text: #ffffff;
            --os-bg: var(--surface);
            --ticker-bg: var(--surface);
        }

        --mono: 'Share Tech Mono', monospace;
        --sans: 'Syne', sans-serif;

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: 'Syne', sans-serif;
            min-height: 100vh;
            overflow-x: hidden;
            transition: background 0.3s, color 0.3s;
        }

        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background-image:
                linear-gradient(var(--grid-color) 1px, transparent 1px),
                linear-gradient(90deg, var(--grid-color) 1px, transparent 1px);
            background-size: 60px 60px;
            animation: gridShift 20s linear infinite;
            pointer-events: none;
            z-index: 0;
        }
        @keyframes gridShift {
            0% { transform: translate(0,0); }
            100% { transform: translate(60px, 60px); }
        }

        body::after {
            content: '';
            position: fixed;
            inset: 0;
            background: radial-gradient(ellipse at center, transparent 40%, var(--bg-vignette) 100%);
            pointer-events: none;
            z-index: 0;
        }

        /* ===== THEME TOGGLE ===== */
        .theme-toggle {
            position: fixed;
            top: 18px;
            right: 20px;
            z-index: 200;
            display: flex;
            align-items: center;
            gap: 8px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 30px;
            padding: 5px 10px 5px 14px;
            cursor: pointer;
            transition: all 0.25s;
            box-shadow: 0 2px 12px rgba(0,0,0,0.15);
        }
        .theme-toggle:hover {
            border-color: var(--accent-border);
            box-shadow: 0 0 16px var(--accent-glow);
        }
        .theme-label {
            font-family: 'Share Tech Mono', monospace;
            font-size: 10px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            user-select: none;
        }
        .toggle-pill {
            width: 36px;
            height: 20px;
            background: var(--surface2);
            border: 1px solid var(--border);
            border-radius: 10px;
            position: relative;
            transition: background 0.3s;
        }
        [data-theme="dark"] .toggle-pill { background: var(--accent-dim); border-color: var(--accent-border); }
        .toggle-knob {
            position: absolute;
            top: 2px;
            width: 14px; height: 14px;
            border-radius: 50%;
            background: var(--muted);
            transition: left 0.3s, background 0.3s;
            left: 2px;
        }
        [data-theme="dark"] .toggle-knob {
            left: 18px;
            background: var(--accent);
            box-shadow: 0 0 6px var(--accent-glow);
        }
        .toggle-icon { font-size: 13px; }

        /* ===== TOP BAR ===== */
        .topbar {
            position: fixed;
            top: 0; left: 0; right: 0;
            height: 3px;
            background: var(--topbar);
            animation: scanBar 3s ease-in-out infinite;
            z-index: 100;
        }
        @keyframes scanBar {
            0%, 100% { opacity: 0.5; }
            50% { opacity: 1; }
        }

        /* ===== PAGE WRAP ===== */
        .page-wrap {
            position: relative;
            z-index: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 40px 20px 80px;
        }

        /* ===== SHIELD ===== */
        .shield-wrap {
            position: relative;
            margin-bottom: 36px;
        }
        .shield {
            width: 90px; height: 90px;
            animation: shieldPulse 3s ease-in-out infinite;
        }
        @keyframes shieldPulse {
            0%, 100% { filter: drop-shadow(0 0 10px var(--accent-glow)); }
            50% { filter: drop-shadow(0 0 26px var(--accent-glow)) drop-shadow(0 0 46px var(--accent-dim)); }
        }
        .shield svg { width: 100%; height: 100%; }
        .orbit {
            position: absolute;
            inset: -16px;
            border: 1px solid var(--orbit-color);
            border-radius: 50%;
            animation: spin 8s linear infinite;
        }
        .orbit::before {
            content: '';
            position: absolute;
            top: -3px; left: 50%;
            width: 6px; height: 6px;
            background: var(--accent);
            border-radius: 50%;
            transform: translateX(-50%);
            box-shadow: 0 0 8px var(--accent-glow);
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        /* ===== HERO TEXT ===== */
        .hero-label {
            font-family: 'Share Tech Mono', monospace;
            color: var(--accent);
            font-size: 11px;
            letter-spacing: 4px;
            text-transform: uppercase;
            margin-bottom: 12px;
            animation: fadeIn 0.8s ease both;
        }
        h1 {
            font-weight: 800;
            font-size: clamp(42px, 8vw, 72px);
            line-height: 1;
            letter-spacing: -2px;
            margin-bottom: 14px;
            animation: fadeIn 0.9s ease both;
        }
        h1 .mal { color: var(--red); }
        .tagline {
            font-family: 'Share Tech Mono', monospace;
            font-size: 13px;
            color: var(--muted);
            margin-bottom: 44px;
            animation: fadeIn 1s ease both;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(16px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* ===== OS CHIP ===== */
        .os-chip {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 9px 18px;
            background: var(--os-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            font-family: 'Share Tech Mono', monospace;
            font-size: 12px;
            color: var(--text);
            margin-bottom: 20px;
            animation: fadeIn 1.1s ease both;
            box-shadow: 0 2px 12px rgba(0,0,0,0.08);
        }
        .os-dot {
            width: 7px; height: 7px;
            background: var(--accent);
            border-radius: 50%;
            box-shadow: 0 0 7px var(--accent-glow);
        }
        .os-label { color: var(--muted); font-size: 10px; margin-right: 2px; }

        /* ===== SCAN BUTTON ===== */
        .scan-btn {
            position: relative;
            display: inline-flex;
            align-items: center;
            gap: 12px;
            padding: 18px 52px;
            background: transparent;
            border: 1.5px solid var(--btn-border);
            border-radius: 6px;
            color: var(--text);
            font-family: 'Syne', sans-serif;
            font-size: 15px;
            font-weight: 700;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            cursor: pointer;
            text-decoration: none;
            overflow: hidden;
            transition: color 0.3s, box-shadow 0.3s;
            animation: fadeIn 1.2s ease both;
        }
        .scan-btn::before {
            content: '';
            position: absolute;
            inset: 0;
            background: var(--btn-bg);
            transform: translateX(-101%);
            transition: transform 0.3s cubic-bezier(0.4,0,0.2,1);
        }
        .scan-btn:hover::before { transform: translateX(0); }
        .scan-btn:hover { color: var(--btn-text); box-shadow: 0 0 32px var(--accent-glow); }
        .scan-btn span, .scan-btn .icon { position: relative; z-index: 1; }
        .scan-btn .icon {
            width: 20px; height: 20px;
            animation: spinIcon 4s linear infinite paused;
        }
        .scan-btn:hover .icon { animation-play-state: running; }
        @keyframes spinIcon { to { transform: rotate(360deg); } }

        /* ===== TICKER ===== */
        .ticker-wrap {
            position: fixed;
            bottom: 0; left: 0; right: 0;
            background: var(--ticker-bg);
            border-top: 1px solid var(--border);
            padding: 10px 0;
            overflow: hidden;
            z-index: 10;
        }
        .ticker {
            display: flex;
            gap: 60px;
            white-space: nowrap;
            animation: ticker 30s linear infinite;
            font-family: 'Share Tech Mono', monospace;
            font-size: 11px;
            color: var(--muted);
        }
        .ticker span { color: var(--accent); }
        @keyframes ticker {
            from { transform: translateX(0); }
            to { transform: translateX(-50%); }
        }
    </style>
</head>
<body>
    <div class="topbar"></div>

    <!-- Theme Toggle -->
    <button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">
        <span class="theme-label" id="theme-label">Dark</span>
        <div class="toggle-pill">
            <div class="toggle-knob"></div>
        </div>
        <span class="toggle-icon" id="theme-icon">🌙</span>
    </button>

    <div class="page-wrap">
        <div class="shield-wrap">
            <div class="orbit"></div>
            <div class="shield">
                <svg viewBox="0 0 90 90" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M45 8L12 22V46C12 63 27 76 45 82C63 76 78 63 78 46V22L45 8Z"
                          fill="var(--shield-fill)" stroke="var(--shield-stroke)" stroke-width="1.5"/>
                    <path d="M45 18L22 29V46C22 58 32 67 45 72C58 67 68 58 68 46V29L45 18Z"
                          fill="var(--shield-fill)" stroke="var(--accent-border)" stroke-width="1"/>
                    <path d="M34 45L41 52L57 38" stroke="var(--shield-stroke)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </div>
        </div>

        <p class="hero-label">// Security Utility v2.0</p>
        <h1><span class="mal">Mal</span>Ext</h1>
        <p class="tagline">Browser Extension Threat Scanner &nbsp;|&nbsp; Chrome · Edge · Brave</p>

        <!-- OS chip centered above button -->
        <div class="os-chip">
            <div class="os-dot"></div>
            <span class="os-label">Detected OS:</span>
            <strong>{{ os }}</strong>
        </div>

        <a href="/scan" class="scan-btn">
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                <path d="M9 12l2 2 4-4"/>
            </svg>
            <span>Initiate Scan</span>
        </a>
    </div>

    <div class="ticker-wrap">
        <div class="ticker">
            <span>⚠</span> Always keep your browser extensions updated &nbsp;·&nbsp;
            <span>ℹ</span> Extensions with broad permissions pose higher risk &nbsp;·&nbsp;
            <span>⚠</span> Disable extensions you don't actively use &nbsp;·&nbsp;
            <span>ℹ</span> Report false positives on GitHub &nbsp;·&nbsp;
            <span>⚠</span> Always keep your browser extensions updated &nbsp;·&nbsp;
            <span>ℹ</span> Extensions with broad permissions pose higher risk &nbsp;·&nbsp;
            <span>⚠</span> Disable extensions you don't actively use &nbsp;·&nbsp;
            <span>ℹ</span> Report false positives on GitHub &nbsp;·&nbsp;
        </div>
    </div>

    <script>
        const THEME_KEY = 'malext-theme';

        function setTheme(theme) {
            document.documentElement.setAttribute('data-theme', theme);
            document.getElementById('theme-label').textContent = theme === 'dark' ? 'Dark' : 'Light';
            document.getElementById('theme-icon').textContent = theme === 'dark' ? '🌙' : '☀️';
            localStorage.setItem(THEME_KEY, theme);
        }

        setTheme(localStorage.getItem(THEME_KEY) || 'light');

        function toggleTheme() {
            const curr = document.documentElement.getAttribute('data-theme');
            setTheme(curr === 'dark' ? 'light' : 'dark');
        }
    </script>
</body>
</html>"""


SCAN_TEMPLATE = """<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
    <title>MalExt — Scan Results</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
        /* ======================================================
           DARK THEME — deep navy/slate with vivid cyan
        ====================================================== */
        [data-theme="dark"] {
            --accent:        #22d3ee;
            --accent-bright: #67e8f9;
            --accent-dim:    rgba(34,211,238,0.10);
            --accent-border: rgba(34,211,238,0.22);
            --accent-glow:   rgba(34,211,238,0.28);
            --red:           #f87171;
            --red-dim:       rgba(248,113,113,0.12);
            --red-border:    rgba(248,113,113,0.28);
            --red-glow:      rgba(248,113,113,0.20);
            --yellow:        #fbbf24;
            --green:         #34d399;
            --bg:            #0a0f1a;
            --bg2:           #0d1422;
            --surface:       #111827;
            --surface2:      #1a2234;
            --surface3:      #1f2a40;
            --border:        rgba(255,255,255,0.07);
            --border2:       rgba(255,255,255,0.04);
            --text:          #f1f5f9;
            --text2:         #94a3b8;
            --muted:         #475569;
            --header-bg:     rgba(10,15,26,0.90);
            --row-hover:     rgba(34,211,238,0.04);
            --threat-row:    rgba(248,113,113,0.06);
            --threat-hover:  rgba(248,113,113,0.10);
            --card-danger:   linear-gradient(135deg,#1c1020,#1a1020);
            --input-bg:      #1a2234;
            --input-focus:   rgba(34,211,238,0.3);
            --tag-enabled-bg:  rgba(52,211,153,0.10);
            --tag-enabled-cl:  #34d399;
            --tag-enabled-br:  rgba(52,211,153,0.25);
            --tag-disabled-bg: rgba(251,191,36,0.10);
            --tag-disabled-cl: #fbbf24;
            --tag-disabled-br: rgba(251,191,36,0.25);
            --sort-active:   #22d3ee;
            --scrollbar-bg:  #1a2234;
            --scrollbar-th:  #2d3f5e;
        }

        /* ======================================================
           LIGHT THEME
        ====================================================== */
        [data-theme="light"] {
            --accent:        #0284c7;
            --accent-bright: #0ea5e9;
            --accent-dim:    rgba(2,132,199,0.08);
            --accent-border: rgba(2,132,199,0.22);
            --accent-glow:   rgba(2,132,199,0.18);
            --red:           #dc2626;
            --red-dim:       rgba(220,38,38,0.07);
            --red-border:    rgba(220,38,38,0.20);
            --red-glow:      rgba(220,38,38,0.12);
            --yellow:        #d97706;
            --green:         #059669;
            --bg:            #f1f5f9;
            --bg2:           #e9eef5;
            --surface:       #ffffff;
            --surface2:      #f8fafc;
            --surface3:      #f1f5f9;
            --border:        rgba(0,0,0,0.08);
            --border2:       rgba(0,0,0,0.04);
            --text:          #0f172a;
            --text2:         #475569;
            --muted:         #94a3b8;
            --header-bg:     rgba(241,245,249,0.92);
            --row-hover:     rgba(2,132,199,0.04);
            --threat-row:    rgba(220,38,38,0.04);
            --threat-hover:  rgba(220,38,38,0.08);
            --card-danger:   linear-gradient(135deg,#fff5f5,#fff0f0);
            --input-bg:      #f8fafc;
            --input-focus:   rgba(2,132,199,0.25);
            --tag-enabled-bg:  rgba(5,150,105,0.08);
            --tag-enabled-cl:  #059669;
            --tag-enabled-br:  rgba(5,150,105,0.2);
            --tag-disabled-bg: rgba(217,119,6,0.08);
            --tag-disabled-cl: #d97706;
            --tag-disabled-br: rgba(217,119,6,0.2);
            --sort-active:   #0284c7;
            --scrollbar-bg:  #f1f5f9;
            --scrollbar-th:  #cbd5e1;
        }

        *, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }

        html { font-size: 14px; }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: 'Syne', sans-serif;
            min-height: 100vh;
            overflow-x: hidden;
            transition: background .3s, color .3s;
        }

        /* Subtle noise/grid bg */
        body::before {
            content:'';
            position:fixed; inset:0;
            background-image:
                linear-gradient(var(--border2) 1px, transparent 1px),
                linear-gradient(90deg, var(--border2) 1px, transparent 1px);
            background-size: 48px 48px;
            pointer-events:none; z-index:0;
        }

        /* Custom scrollbar */
        ::-webkit-scrollbar { width:6px; height:6px; }
        ::-webkit-scrollbar-track { background: var(--scrollbar-bg); }
        ::-webkit-scrollbar-thumb { background: var(--scrollbar-th); border-radius:3px; }

        /* ===== HEADER ===== */
        .header {
            position: sticky; top:0; z-index:200;
            background: var(--header-bg);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border-bottom: 1px solid var(--border);
            padding: 0 20px;
            height: 56px;
            display: flex; align-items:center; justify-content:space-between;
            gap: 12px;
            transition: background .3s;
        }

        .header::after {
            content:'';
            position:absolute; bottom:0; left:0; right:0; height:1px;
            background: linear-gradient(90deg, transparent, var(--accent), transparent);
            animation: scanLine 4s ease-in-out infinite;
        }
        @keyframes scanLine {
            0%   { opacity:0; transform:scaleX(0); }
            20%  { opacity:1; }
            80%  { opacity:1; }
            100% { opacity:0; transform:scaleX(1); }
        }

        .header-left { display:flex; align-items:center; gap:14px; flex-shrink:0; }

        .back-link {
            display:inline-flex; align-items:center; gap:5px;
            color: var(--text2); text-decoration:none;
            font-family:'Share Tech Mono',monospace; font-size:11px;
            padding:5px 10px; border-radius:4px;
            border:1px solid var(--border);
            background: var(--surface2);
            transition: all .2s;
            white-space:nowrap;
        }
        .back-link:hover { color:var(--text); border-color:var(--accent-border); }

        .logo { font-weight:800; font-size:18px; letter-spacing:-0.5px; white-space:nowrap; }
        .logo .mal { color:var(--red); }
        .logo .ext { color:var(--accent); }

        .header-right { display:flex; align-items:center; gap:8px; flex-shrink:0; }

        .hbadge {
            display:inline-flex; align-items:center; gap:5px;
            padding:4px 10px; border-radius:20px;
            font-family:'Share Tech Mono',monospace; font-size:11px; font-weight:600;
            white-space:nowrap;
        }
        .hbadge.danger { background:var(--red-dim); border:1px solid var(--red-border); color:var(--red); }
        .hbadge.safe   { background:var(--accent-dim); border:1px solid var(--accent-border); color:var(--accent); }
        .hbadge .dot   { width:5px;height:5px;border-radius:50%;background:currentColor; }

        .ts {
            font-family:'Share Tech Mono',monospace; font-size:10px;
            color:var(--muted); white-space:nowrap;
            display:none;
        }
        @media(min-width:640px){ .ts { display:inline; } }

        /* Theme toggle */
        .theme-btn {
            display:inline-flex; align-items:center; gap:6px;
            background:var(--surface2); border:1px solid var(--border);
            border-radius:20px; padding:4px 10px 4px 12px;
            cursor:pointer; transition:all .25s; white-space:nowrap;
        }
        .theme-btn:hover { border-color:var(--accent-border); box-shadow:0 0 10px var(--accent-glow); }
        .theme-btn-label { font-family:'Share Tech Mono',monospace; font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; }
        .tpill { width:30px;height:17px;background:var(--surface3);border:1px solid var(--border);border-radius:9px;position:relative;transition:background .3s; }
        [data-theme="dark"] .tpill { background:var(--accent-dim);border-color:var(--accent-border); }
        .tknob { position:absolute;top:1.5px;left:1.5px;width:12px;height:12px;border-radius:50%;background:var(--muted);transition:left .3s,background .3s; }
        [data-theme="dark"] .tknob { left:14px;background:var(--accent);box-shadow:0 0 5px var(--accent-glow); }

        /* ===== MAIN ===== */
        .main {
            position:relative; z-index:1;
            max-width:1200px; margin:0 auto;
            padding:24px 16px 60px;
            width:100%;
        }

        /* ===== CARDS ===== */
        .cards {
            display:grid;
            grid-template-columns:repeat(4,1fr);
            gap:10px; margin-bottom:28px;
        }
        @media(max-width:640px){ .cards { grid-template-columns:repeat(2,1fr); } }

        .card {
            background:var(--surface); border:1px solid var(--border);
            border-radius:10px; padding:16px 18px;
            position:relative; overflow:hidden;
            animation: fadeUp .4s ease both;
        }
        .card:nth-child(1){animation-delay:.05s}
        .card:nth-child(2){animation-delay:.1s}
        .card:nth-child(3){animation-delay:.15s}
        .card:nth-child(4){animation-delay:.2s}

        @keyframes fadeUp {
            from { opacity:0; transform:translateY(14px); }
            to   { opacity:1; transform:translateY(0); }
        }

        .card::before {
            content:''; position:absolute; top:0;left:0;right:0; height:2px;
            background: var(--border);
        }
        .card.c-accent::before { background:var(--accent); }
        .card.c-red::before    { background:var(--red); }
        .card.c-green::before  { background:var(--green); }

        .card-val {
            font-family:'Share Tech Mono',monospace; font-size:32px; line-height:1;
            margin-bottom:5px; color:var(--text);
        }
        .card.c-accent .card-val { color:var(--accent); }
        .card.c-red    .card-val { color:var(--red); }
        .card.c-green  .card-val { color:var(--green); }
        .card-lbl { font-size:10px; text-transform:uppercase; letter-spacing:1.5px; color:var(--muted); }

        /* ===== ALL-CLEAR ===== */
        .all-clear {
            display:flex; align-items:center; gap:16px;
            background:var(--accent-dim); border:1px solid var(--accent-border);
            border-radius:10px; padding:20px 24px; margin-bottom:28px;
            animation: fadeUp .4s ease both;
        }
        .all-clear-icon { font-size:32px; flex-shrink:0; }
        .all-clear h3 { font-size:16px; font-weight:700; color:var(--accent); margin-bottom:3px; }
        .all-clear p  { font-family:'Share Tech Mono',monospace; font-size:11px; color:var(--text2); }

        /* ===== SECTION HEADER ===== */
        .sec-hdr {
            display:flex; align-items:center; gap:10px;
            margin-bottom:12px; padding-bottom:12px;
            border-bottom:1px solid var(--border);
        }
        .sec-icon { font-size:18px; }
        .sec-title { font-weight:700; font-size:15px; }
        .sec-badge {
            margin-left:auto;
            font-family:'Share Tech Mono',monospace; font-size:11px;
            padding:2px 10px; border-radius:10px;
        }
        .sec-badge.red   { background:var(--red-dim);    color:var(--red);    border:1px solid var(--red-border); }
        .sec-badge.green { background:var(--accent-dim); color:var(--accent); border:1px solid var(--accent-border); }

        /* ===== DATATABLE CONTROLS ===== */
        .dt-controls {
            display:flex; flex-wrap:wrap; align-items:center;
            gap:8px; margin-bottom:10px;
        }

        .dt-search-wrap {
            position:relative; flex:1; min-width:180px;
        }
        .dt-search-wrap svg {
            position:absolute; left:10px; top:50%; transform:translateY(-50%);
            color:var(--muted); pointer-events:none; flex-shrink:0;
        }
        .dt-search {
            width:100%; padding:8px 12px 8px 34px;
            background:var(--input-bg); border:1px solid var(--border);
            border-radius:6px; color:var(--text);
            font-family:'Share Tech Mono',monospace; font-size:12px;
            outline:none; transition:border-color .2s, box-shadow .2s;
        }
        .dt-search:focus {
            border-color:var(--accent-border);
            box-shadow: 0 0 0 3px var(--input-focus);
        }
        .dt-search::placeholder { color:var(--muted); }

        .dt-filters { display:flex; gap:6px; flex-wrap:wrap; }
        .flt {
            padding:5px 11px; border-radius:4px;
            border:1px solid var(--border); background:var(--surface2);
            color:var(--muted); font-family:'Share Tech Mono',monospace;
            font-size:11px; cursor:pointer; transition:all .18s;
            white-space:nowrap;
        }
        .flt:hover { color:var(--text); border-color:var(--accent-border); }
        .flt.active {
            background:var(--accent-dim); color:var(--accent);
            border-color:var(--accent-border);
        }

        .dt-per-page {
            display:flex; align-items:center; gap:6px;
            font-family:'Share Tech Mono',monospace; font-size:11px; color:var(--muted);
            white-space:nowrap;
        }
        .dt-per-page select {
            padding:5px 8px; background:var(--input-bg); border:1px solid var(--border);
            border-radius:4px; color:var(--text);
            font-family:'Share Tech Mono',monospace; font-size:11px; cursor:pointer; outline:none;
        }
        .dt-per-page select:focus { border-color:var(--accent-border); }

        /* ===== TABLE WRAPPER — responsive scroll ===== */
        .tbl-outer {
            background:var(--surface); border:1px solid var(--border);
            border-radius:10px; overflow:hidden;
            margin-bottom:28px; animation: fadeUp .4s ease both;
            /* Key fix: contain overflow */
            width:100%; max-width:100%;
        }
        .tbl-outer.threat { border-color:var(--red-border); }
        .tbl-outer.clean  { border-color:var(--accent-border); }

        .tbl-scroll {
            width:100%; overflow-x:auto;
            -webkit-overflow-scrolling:touch;
        }

        table {
            width:100%; border-collapse:collapse;
            /* Prevent table from expanding beyond container */
            table-layout:fixed;
        }

        /* Column widths */
        table.ext-table col.c-name    { width:28%; }
        table.ext-table col.c-browser { width:12%; }
        table.ext-table col.c-profile { width:13%; }
        table.ext-table col.c-status  { width:12%; }
        table.ext-table col.c-threat  { width:13%; }

        thead tr { background:var(--surface2); }

        th {
            padding:10px 14px;
            text-align:left; font-size:10px;
            text-transform:uppercase; letter-spacing:1.5px;
            color:var(--muted); font-weight:600;
            border-bottom:1px solid var(--border);
            cursor:pointer; user-select:none;
            transition:color .18s; white-space:nowrap;
            position:relative;
        }
        th:hover { color:var(--text); }
        th.sorted-asc,
        th.sorted-desc { color:var(--sort-active); }
        th .sort-ico {
            display:inline-block; margin-left:4px;
            font-size:9px; opacity:.35;
            transition:opacity .18s;
        }
        th:hover .sort-ico,
        th.sorted-asc .sort-ico,
        th.sorted-desc .sort-ico { opacity:1; }
        th.sorted-asc  .sort-ico::after { content:'↑'; }
        th.sorted-desc .sort-ico::after { content:'↓'; }
        th:not(.sorted-asc):not(.sorted-desc) .sort-ico::after { content:'↕'; }

        tbody tr {
            border-bottom:1px solid var(--border2);
            transition:background .12s;
        }
        tbody tr:last-child { border-bottom:none; }
        tbody tr:hover { background:var(--row-hover); }
        .threat-row { background:var(--threat-row); }
        .threat-row:hover { background:var(--threat-hover) !important; }

        td {
            padding:10px 14px; font-size:13px;
            vertical-align:middle;
            /* prevent overflow */
            overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
        }
        td.td-name { white-space:normal; }

        .ext-name { font-weight:600; font-size:13px; color:var(--text); line-height:1.3; }
        .ext-id {
            display:block; font-family:'Share Tech Mono',monospace;
            font-size:10px; color:var(--muted); margin-top:2px;
            overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
        }

        .br-badge {
            display:inline-flex; align-items:center;
            padding:2px 8px; border-radius:3px;
            font-size:10px; font-weight:700;
            background:var(--surface3); border:1px solid var(--border);
            color:var(--text2); letter-spacing:.3px;
        }

        .spill {
            display:inline-flex; align-items:center; gap:4px;
            padding:2px 9px; border-radius:20px;
            font-family:'Share Tech Mono',monospace;
            font-size:10px; font-weight:700;
        }
        .spill-dot { width:5px;height:5px;border-radius:50%;background:currentColor; }
        .spill.enabled  { background:var(--tag-enabled-bg);  color:var(--tag-enabled-cl);  border:1px solid var(--tag-enabled-br); }
        .spill.disabled { background:var(--tag-disabled-bg); color:var(--tag-disabled-cl); border:1px solid var(--tag-disabled-br); }
        .spill.unknown  { background:var(--surface3); color:var(--muted); border:1px solid var(--border); }

        .threat-pill {
            display:inline-flex; align-items:center; gap:5px;
            font-family:'Share Tech Mono',monospace; font-size:10px;
            color:var(--red); font-weight:700; letter-spacing:.5px;
        }
        .tpulse {
            width:7px;height:7px;border-radius:50%;background:var(--red);
            animation:tpulse 1.6s ease infinite;
        }
        @keyframes tpulse {
            0%  { box-shadow:0 0 0 0 var(--red-glow); }
            70% { box-shadow:0 0 0 6px transparent; }
            100%{ box-shadow:0 0 0 0 transparent; }
        }

        /* ===== TABLE FOOTER / PAGINATION ===== */
        .tbl-footer {
            display:flex; align-items:center; justify-content:space-between;
            flex-wrap:wrap; gap:8px;
            padding:10px 14px;
            border-top:1px solid var(--border);
            background:var(--surface2);
            font-family:'Share Tech Mono',monospace; font-size:11px; color:var(--muted);
        }

        .pagination { display:flex; gap:4px; }
        .pg-btn {
            min-width:28px; height:28px; padding:0 6px;
            display:inline-flex; align-items:center; justify-content:center;
            border-radius:5px; border:1px solid var(--border);
            background:var(--surface3); color:var(--text2);
            font-family:'Share Tech Mono',monospace; font-size:11px;
            cursor:pointer; transition:all .18s;
        }
        .pg-btn:hover { border-color:var(--accent-border); color:var(--accent); }
        .pg-btn.active {
            background:var(--accent-dim); border-color:var(--accent-border);
            color:var(--accent); font-weight:700;
        }
        .pg-btn:disabled { opacity:.3; cursor:default; pointer-events:none; }

        /* Empty state */
        .empty {
            padding:48px 20px; text-align:center;
        }
        .empty-icon { font-size:36px; margin-bottom:12px; opacity:.4; }
        .empty-msg { font-family:'Share Tech Mono',monospace; font-size:12px; color:var(--muted); }

        /* No results row */
        .no-results { display:none; }
        .no-results td {
            text-align:center; padding:30px;
            font-family:'Share Tech Mono',monospace; font-size:12px; color:var(--muted);
        }
    </style>
</head>
<body>

<header class="header">
    <div class="header-left">
        <a href="/" class="back-link">← Home</a>
        <div class="logo"><span class="mal">Mal</span><span class="ext">Ext</span></div>
    </div>
    <div class="header-right">
        {% if mal_count > 0 %}
        <div class="hbadge danger"><div class="dot"></div>{{ mal_count }} Threat{{ 's' if mal_count != 1 }}</div>
        {% else %}
        <div class="hbadge safe"><div class="dot"></div>All Clear</div>
        {% endif %}
        <span class="ts" id="scan-time"></span>
        <button class="theme-btn" onclick="toggleTheme()">
            <span class="theme-btn-label" id="theme-label">Dark</span>
            <div class="tpill"><div class="tknob"></div></div>
            <span id="theme-icon">🌙</span>
        </button>
    </div>
</header>

<main class="main">

    <!-- Summary Cards -->
    <div class="cards">
        <div class="card c-accent">
            <div class="card-val">{{ total }}</div>
            <div class="card-lbl">Total Scanned</div>
        </div>
        <div class="card {% if mal_count > 0 %}c-red{% else %}c-accent{% endif %}">
            <div class="card-val">{{ mal_count }}</div>
            <div class="card-lbl">Threats Found</div>
        </div>
        <div class="card c-green">
            <div class="card-val">{{ clean_count }}</div>
            <div class="card-lbl">Clean</div>
        </div>
        <div class="card">
            <div class="card-val" id="risk-score">—</div>
            <div class="card-lbl">Risk Score</div>
        </div>
    </div>

    {% if mal_count == 0 %}
    <div class="all-clear">
        <div class="all-clear-icon">🛡️</div>
        <div>
            <h3>No Threats Detected</h3>
            <p>All {{ total }} extension{{ 's' if total != 1 }} scanned — none matched the malicious extensions database.</p>
        </div>
    </div>
    {% endif %}

    <!-- ===== MALICIOUS TABLE ===== -->
    {% if mal_count > 0 %}
    <div class="sec-hdr">
        <span class="sec-icon">🚨</span>
        <span class="sec-title">Malicious Extensions</span>
        <span class="sec-badge red">{{ mal_count }} found</span>
    </div>

    <div class="tbl-outer threat">
        <div class="tbl-scroll">
        <table class="ext-table" id="mal-table">
            <colgroup>
                <col class="c-name">
                <col class="c-browser">
                <col class="c-profile">
                <col class="c-status">
                <col class="c-threat">
            </colgroup>
            <thead>
                <tr>
                    <th onclick="sortTbl('mal-table',0,this)">Extension <span class="sort-ico"></span></th>
                    <th onclick="sortTbl('mal-table',1,this)">Browser <span class="sort-ico"></span></th>
                    <th onclick="sortTbl('mal-table',2,this)">Profile <span class="sort-ico"></span></th>
                    <th onclick="sortTbl('mal-table',3,this)">Status <span class="sort-ico"></span></th>
                    <th>Threat</th>
                </tr>
            </thead>
            <tbody>
                {% for ext in malicious_ext %}
                <tr class="threat-row">
                    <td class="td-name">
                        <div class="ext-name">{{ ext.name }}</div>
                        <span class="ext-id">{{ ext.id }}</span>
                    </td>
                    <td><span class="br-badge">{{ ext.browser }}</span></td>
                    <td style="font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--muted)">{{ ext.profile }}</td>
                    <td>
                        {% if ext.status == "Enabled" %}
                            <span class="spill enabled"><span class="spill-dot"></span>Enabled</span>
                        {% elif ext.status == "Disabled" %}
                            <span class="spill disabled"><span class="spill-dot"></span>Disabled</span>
                        {% else %}
                            <span class="spill unknown"><span class="spill-dot"></span>Unknown</span>
                        {% endif %}
                    </td>
                    <td>
                        <div class="threat-pill"><div class="tpulse"></div>MALICIOUS</div>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        </div>
        <div class="tbl-footer">
            <span>{{ mal_count }} threat{{ 's' if mal_count != 1 }} detected</span>
            <span>Matched against known malicious extensions DB</span>
        </div>
    </div>
    {% endif %}

    <!-- ===== CLEAN TABLE ===== -->
    <div class="sec-hdr">
        <span class="sec-icon">✅</span>
        <span class="sec-title">Clean Extensions</span>
        <span class="sec-badge green" id="clean-sec-count">{{ clean_count }} verified</span>
    </div>

    <!-- DataTable controls -->
    <div class="dt-controls">
        <div class="dt-search-wrap">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
            </svg>
            <input class="dt-search" id="clean-search" type="text"
                   placeholder="Search by name, ID, browser, profile…"
                   oninput="dtFilter()">
        </div>
        <div class="dt-filters">
            <button class="flt active" data-status="all"      onclick="dtStatusFilter(this)">All</button>
            <button class="flt"        data-status="Enabled"  onclick="dtStatusFilter(this)">Enabled</button>
            <button class="flt"        data-status="Disabled" onclick="dtStatusFilter(this)">Disabled</button>
            <button class="flt"        data-status="Unknown"  onclick="dtStatusFilter(this)">Unknown</button>
        </div>
        <div class="dt-per-page">
            Show
            <select id="dt-page-size" onchange="dtChangePageSize()">
                <option value="10">10</option>
                <option value="25" selected>25</option>
                <option value="50">50</option>
                <option value="100">100</option>
                <option value="999999">All</option>
            </select>
            entries
        </div>
    </div>

    <div class="tbl-outer clean">
        {% if clean_count == 0 %}
        <div class="empty">
            <div class="empty-icon">📭</div>
            <div class="empty-msg">No extensions to display.</div>
        </div>
        {% else %}
        <div class="tbl-scroll">
        <table class="ext-table" id="clean-table">
            <colgroup>
                <col class="c-name">
                <col class="c-browser">
                <col class="c-profile">
                <col class="c-status">
            </colgroup>
            <thead>
                <tr>
                    <th onclick="sortTbl('clean-table',0,this)">Extension <span class="sort-ico"></span></th>
                    <th onclick="sortTbl('clean-table',1,this)">Browser <span class="sort-ico"></span></th>
                    <th onclick="sortTbl('clean-table',2,this)">Profile <span class="sort-ico"></span></th>
                    <th onclick="sortTbl('clean-table',3,this)">Status <span class="sort-ico"></span></th>
                </tr>
            </thead>
            <tbody id="clean-tbody">
                {% for ext in clean_ext %}
                <tr data-status="{{ ext.status }}"
                    data-search="{{ (ext.name ~ ' ' ~ ext.id ~ ' ' ~ ext.browser ~ ' ' ~ ext.profile)|lower }}">
                    <td class="td-name">
                        <div class="ext-name">{{ ext.name }}</div>
                        <span class="ext-id">{{ ext.id }}</span>
                    </td>
                    <td><span class="br-badge">{{ ext.browser }}</span></td>
                    <td style="font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--muted)">{{ ext.profile }}</td>
                    <td>
                        {% if ext.status == "Enabled" %}
                            <span class="spill enabled"><span class="spill-dot"></span>Enabled</span>
                        {% elif ext.status == "Disabled" %}
                            <span class="spill disabled"><span class="spill-dot"></span>Disabled</span>
                        {% else %}
                            <span class="spill unknown"><span class="spill-dot"></span>Unknown</span>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
                <tr class="no-results" id="no-results-row">
                    <td colspan="4">No extensions match your search.</td>
                </tr>
            </tbody>
        </table>
        </div>
        <div class="tbl-footer">
            <span id="dt-info">Showing all {{ clean_count }} entries</span>
            <div class="pagination" id="dt-pagination"></div>
        </div>
        {% endif %}
    </div>

</main>

<script>
// ── Theme ──────────────────────────────────────────
const TK = 'malext-theme';
function applyTheme(t){
    document.documentElement.setAttribute('data-theme',t);
    const lbl = document.getElementById('theme-label');
    const ico = document.getElementById('theme-icon');
    if(lbl) lbl.textContent = t==='dark'?'Dark':'Light';
    if(ico) ico.textContent = t==='dark'?'🌙':'☀️';
    localStorage.setItem(TK,t);
}
applyTheme(localStorage.getItem(TK) || 'light');
function toggleTheme(){
    applyTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark');
}

// ── Scan time ──────────────────────────────────────
const el = document.getElementById('scan-time');
if(el) el.textContent = 'Scanned '+new Date().toLocaleTimeString();

// ── Risk score ─────────────────────────────────────
const total = {{ total }}, malCnt = {{ mal_count }};
const rEl = document.getElementById('risk-score');
if(rEl){
    if(total===0){ rEl.textContent='N/A'; }
    else{
        const s=Math.round(malCnt/total*100);
        rEl.textContent=s+'%';
        if(s>0) rEl.style.color='var(--red)';
    }
}

// ── Sort ───────────────────────────────────────────
const sortState = {};
function sortTbl(tid, col, thEl){
    const tbl = document.getElementById(tid);
    if(!tbl) return;
    const tbody = tbl.querySelector('tbody');
    const key = tid+'-'+col;
    const asc = sortState[key] === undefined ? true : !sortState[key];
    sortState[key] = asc;

    // Update header classes
    tbl.querySelectorAll('th').forEach(t=>{
        t.classList.remove('sorted-asc','sorted-desc');
    });
    if(thEl) thEl.classList.add(asc?'sorted-asc':'sorted-desc');

    const rows = Array.from(tbody.querySelectorAll('tr:not(#no-results-row)'));
    rows.sort((a,b)=>{
        const at = (a.cells[col]?.textContent||'').trim().toLowerCase();
        const bt = (b.cells[col]?.textContent||'').trim().toLowerCase();
        return asc ? at.localeCompare(bt) : bt.localeCompare(at);
    });
    rows.forEach(r=>tbody.appendChild(r));

    if(tid==='clean-table') dtRender();
}

// ── DataTable ──────────────────────────────────────
let dtStatus = 'all';
let dtPage   = 1;
let dtVisible = [];  // indices of currently matching rows

function getAllRows(){
    return Array.from(document.querySelectorAll('#clean-tbody tr:not(#no-results-row)'));
}

function dtFilter(){
    dtPage = 1;
    dtRender();
}

function dtStatusFilter(btn){
    document.querySelectorAll('.flt').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    dtStatus = btn.getAttribute('data-status');
    dtPage = 1;
    dtRender();
}

function dtChangePageSize(){
    dtPage = 1;
    dtRender();
}

function dtRender(){
    const query   = (document.getElementById('clean-search')?.value||'').toLowerCase().trim();
    const pgSize  = parseInt(document.getElementById('dt-page-size')?.value||'25');
    const rows    = getAllRows();

    dtVisible = [];
    rows.forEach((row,i)=>{
        const searchStr = row.getAttribute('data-search')||row.textContent.toLowerCase();
        const st  = row.getAttribute('data-status');
        const okQ = !query || searchStr.includes(query);
        const okS = dtStatus==='all' || st===dtStatus;
        if(okQ && okS) dtVisible.push(i);
        row.style.display = 'none';
    });

    const total = dtVisible.length;
    const noRow = document.getElementById('no-results-row');

    if(total===0){
        if(noRow) noRow.style.display='';
    } else {
        if(noRow) noRow.style.display='none';
        const start = (dtPage-1)*pgSize;
        const end   = pgSize >= 999999 ? total : Math.min(start+pgSize, total);
        dtVisible.slice(start,end).forEach(i=>{ rows[i].style.display=''; });
    }

    // Info text
    const pgSize2 = pgSize >= 999999 ? total : pgSize;
    const from = total===0 ? 0 : (dtPage-1)*pgSize2+1;
    const to   = Math.min(dtPage*pgSize2, total);
    const infoEl = document.getElementById('dt-info');
    if(infoEl){
        const suffix = query||dtStatus!=='all' ? ` (filtered from {{ clean_count }} total)` : '';
        infoEl.textContent = total===0
            ? 'No entries found'
            : pgSize >= 999999
                ? `Showing all ${total} entries${suffix}`
                : `Showing ${from}–${to} of ${total} entries${suffix}`;
    }

    // Pagination
    buildPagination(total, pgSize);

    // Section badge
    const sb = document.getElementById('clean-sec-count');
    if(sb) sb.textContent = total + ' entries';
}

function buildPagination(total, pgSize){
    const pg = document.getElementById('dt-pagination');
    if(!pg) return;
    if(pgSize >= 999999){ pg.innerHTML=''; return; }

    const pages = Math.ceil(total/pgSize);
    if(pages<=1){ pg.innerHTML=''; return; }

    let html = '';
    html += `<button class="pg-btn" onclick="dtGoPage(${dtPage-1})" ${dtPage===1?'disabled':''}>‹</button>`;

    const delta=2;
    for(let p=1;p<=pages;p++){
        if(p===1||p===pages||Math.abs(p-dtPage)<=delta){
            html += `<button class="pg-btn ${p===dtPage?'active':''}" onclick="dtGoPage(${p})">${p}</button>`;
        } else if(Math.abs(p-dtPage)===delta+1){
            html += `<button class="pg-btn" disabled>…</button>`;
        }
    }

    html += `<button class="pg-btn" onclick="dtGoPage(${dtPage+1})" ${dtPage===pages?'disabled':''}>›</button>`;
    pg.innerHTML = html;
}

function dtGoPage(p){
    dtPage = p;
    dtRender();
    document.querySelector('.tbl-outer.clean')?.scrollIntoView({behavior:'smooth',block:'nearest'});
}

// Init
dtRender();
</script>
</body>
</html>"""


# ==========================================================
# ROUTES
# ==========================================================

@app.route("/")
def home():
    return render_template_string(HOME_TEMPLATE, os=platform.system())


@app.route("/scan")
def scan():
    malicious_ids = download_database()
    extensions = get_extensions()

    malicious_ext = [e for e in extensions if e["id"] in malicious_ids]
    clean_ext = [e for e in extensions if e["id"] not in malicious_ids]

    return render_template_string(
        SCAN_TEMPLATE,
        total=len(extensions),
        mal_count=len(malicious_ext),
        clean_count=len(clean_ext),
        malicious_ext=malicious_ext,
        clean_ext=clean_ext
    )


if __name__ == "__main__":
    webbrowser.open("http://127.0.0.1:8989")
    app.run(port=8989, debug=False)