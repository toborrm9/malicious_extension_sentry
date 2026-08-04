<a href="https://www.buymeacoffee.com/toborrm9" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>   
[![Last Updated](https://img.shields.io/badge/Last%20Updated-2026--08--04-blue)](https://github.com/toborrm9/malicious_extension_sentry/blob/main/Malicious-Extensions.md)
[![Last Updated](https://img.shields.io/badge/Total%20Extensions-5252-red)](https://github.com/toborrm9/malicious_extension_sentry/blob/main/Malicious-Extensions.md)
[![Chrome Web Store](https://img.shields.io/chrome-web-store/v/bpohikihiogjgmebpnbgnloipjaddibe?label=MalExt%20Sentry%20Extension&logo=googlechrome&logoColor=white&color=4fcf6c)](https://chromewebstore.google.com/detail/malext-sentry/bpohikihiogjgmebpnbgnloipjaddibe)

# Malicious Chrome/Edge Extensions Database

An automatically updated database of Chrome extensions removed from the Chrome Web Store for containing malware, policy violation, or bundling unwanted software 

## 🌐 Live Dashboard

[![Live Dashboard](https://img.shields.io/badge/Dashboard-malext.io-22c55e?style=for-the-badge&logo=googlechrome&logoColor=white)](https://malext.io)

> Real-time search, filtering by threat category, and source reports,  built on top of this database.

## 📖 Overview

This repository maintains a current list of Chrome extensions that have been removed for malware, security violations, or malicious behavior. Since no regularly-updated public database exists for this purpose, this project automates the collection and aggregation of extension removals from multiple sources.

I created this project after searching for an updated list of malicious Chrome extensions and finding that most resources were outdated or incomplete. I'm committed to keeping this database alive and current through automated monitoring and community contributions.

---

## 🔍 MalExt Scanner

**⚡ Check YOUR extensions right now!**

### Quick Start


Prefer a GUI? The [MalExt Sentry Chrome extension](https://chromewebstore.google.com/detail/malext-sentry/bpohikihiogjgmebpnbgnloipjaddibe) scans automatically every 6 hours in the background.

> ⚠️ **Note:** The extension scans per browser profile. If you use multiple profiles, install it in each one.

**One-line install & scan:**

**Linux & macOS:**
```bash
curl -O https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/malext.py && python3 malext.py
```

**Windows PowerShell < v7:**
```pwsh
Invoke-WebRequest -Uri https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/malext.py -OutFile malext.py; python3 malext.py
```

**Windows PowerShell >= v7:**
```pwsh
Invoke-WebRequest -Uri https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/malext.py -OutFile malext.py && python3 malext.py
```

### ✨ Features

- ✅ **Cross-platform** - Windows, macOS, Linux
- 🔍 **Instant scan** - Chrome, Edge, Chromium, Brave, Vivaldi, Opera + auto-discovered Chromium-based browsers
- 🌐 **Auto-updates** - Downloads latest database
- 🛡️ **Zero install** - Just Python 3
- 🔒 **Privacy-first** - 100% local scanning

### 📸 Example Output

<details>
<summary>Click to see example scan results</summary>

**When safe:**
```
╔════════════════════════════════════════════════════════════════════╗
║        ███╗   ███╗ █████╗ ██╗     ███████╗██╗  ██╗████████╗      ║
║        ████╗ ████║██╔══██╗██║     ██╔════╝╚██╗██╔╝╚══██╔══╝      ║
║        ██╔████╔██║███████║██║     █████╗   ╚███╔╝    ██║         ║
║        ██║╚██╔╝██║██╔══██║██║     ██╔══╝   ██╔██╗    ██║         ║
║        ██║ ╚═╝ ██║██║  ██║███████╗███████╗██╔╝ ██╗   ██║         ║
║        ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝         ║
║              🛡️  Malicious Extension Scanner v1.0 🛡️              ║
║                    Created by: @toborrm9                          ║
╚════════════════════════════════════════════════════════════════════╝

💻 Detected OS: macOS
✅ Loaded 437 known malicious extension IDs
✅ Found 12 extensions (Chrome: 8, Edge: 4)

======================================================================
📊 SCAN RESULTS
======================================================================

✅ GOOD NEWS: No malicious extensions detected!
   All 12 extensions are clear.
```

**When threats found:**
```
⚠️  WARNING: 1 MALICIOUS EXTENSION(S) DETECTED!

🔴 REMOVE THESE IMMEDIATELY:
----------------------------------------------------------------------
❌ Malicious Extension
   ID: abcdefghijklmnopqrstuvwxyz123456
   Browser: Chrome (Default)

🛡️  HOW TO REMOVE:
   1. Open Chrome
   2. Go to chrome://extensions
   3. Find the extension and click 'Remove'
```
</details>

---



## 📰 Recent Security News

- **2026-03-09**: [Chrome Extension Turns Malicious After Ownership Transfer, Enabling Code Injection and Data Theft](https://thehackernews.com/2026/03/chrome-extension-turns-malicious-after.html)
- **2026-02-13**: [Malicious Chrome Extensions Caught Stealing Business Data, Emails, and Browsing History](https://thehackernews.com/2026/02/malicious-chrome-extensions-caught.html)
- **2026-02-13**: [Malicious Chrome Extension Steals Meta Business Manager Exports and TOTP 2FA Seeds](https://socket.dev/blog/malicious-chrome-extension-steals-meta-business-manager-exports-and-totp-2fa-seeds)
- **2026-02-12**: [AiFrame”- Fake AI Assistant Extensions Targeting 260,000 Chrome Users via injected iframes](https://layerxsecurity.com/blog/aiframe-fake-ai-assistant-extensions-targeting-260000-chrome-users-via-injected-iframes/)
- **2026-01-28**: [Malicious Chrome extensions can spy on your ChatGPT chats](https://www.malwarebytes.com/blog/news/2026/01/malicious-chrome-extensions-can-spy-on-your-chatgpt-chats)
- **2026-01-27**: [Small Tools, Big Risk: When Browser Extensions Start Stealing API Keys](https://www.obsidiansecurity.com/blog/small-tools-big-risk-when-browser-extensions-start-stealing-api-keys)
- **2026-01-27**: [Stanley — A $6,000 Russian Malware Toolkit with Chrome Web Store Guarantee](https://www.varonis.com/blog/stanley-malware-kit)
- **2026-01-27**: [Malicious Chrome Extension Performs Hidden Affiliate Hijacking](https://socket.dev/blog/malicious-chrome-extension-performs-hidden-affiliate-hijacking)
- **2026-01-26**: [How We Discovered A Campaign of 16 Malicious Extensions Built to Steal ChatGPT Accounts](https://layerxsecurity.com/blog/how-we-discovered-a-campaign-of-16-malicious-extensions-chatgpt/)
- **2026-01-26**: [Chrome Extensions: Are you getting more than you bargained for?](https://www.security.com/threat-intelligence/chrome-extensions-are-you-getting-more-you-bargained)
- **2025-12-24**: [Silent Takeover: How Purchased Chrome Extensions Became Remote-Controlled Webpage Manipulation Tools](https://layerxsecurity.com/blog/silent-takeover-how-purchased-chrome-extensions-became-remote-controlled-webpage-manipulation-tools/)
- **2025-12-15**: [8 Million Users' AI Conversations Sold for Profit by "Privacy" Extensions](https://www.koi.ai/blog/urban-vpn-browser-extension-ai-conversations-data-collection)
- **2025-12-01**: [4.3 Million Browsers Infected: Inside ShadyPanda's 7-Year Malware Campaign](https://www.koi.ai/blog/4-million-browsers-infected-inside-shadypanda-7-year-malware-campaign)

## 📊 Data Sources

The database is automatically updated by aggregating information from:
- Chrome extension monitoring services
- Security research blogs and publications
- Threat intelligence feeds

## 🗃️ Database Structure

Each extension entry includes:
- **Extension ID** - Unique Chrome Web Store identifier
- **Name** - Extension name
- **Date Added** - When the extension was added to this database

## 🎯 Usage

This database is intended for:
- Security research
- Extension vetting and analysis
- Building protective tools
- Threat intelligence

## 📁 Data Format

Data is available in multiple formats:
- `.md` - Markdown table
- `.csv` - Comma-separated values

## 🤝 Contributing

If you're aware of a malicious extension that should be included, please open an issue with:
- Extension ID
- Evidence or source of malicious behavior
- Date of discovery/removal

## ⚠️ Disclaimer

This database is provided for research and educational purposes. The information is aggregated from public sources and automated monitoring. While efforts are made to ensure accuracy, false positives may occur. Always verify findings before taking action.

---

**Made with ❤️ for browser security**

⭐ **Found this useful?** Star the repo and share with others!
