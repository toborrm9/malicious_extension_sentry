<a href="https://www.buymeacoffee.com/toborrm9" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>

# Malicious Chrome/Edge Extensions Database

An automatically updated database of malicious Chrome extensions removed from the Chrome Web Store.

## Overview

This repository maintains a current list of Chrome extensions that have been removed for malware, security violations, or malicious behavior. Since no regularly-updated public database exists for this purpose, this project automates the collection and aggregation of extension removals from multiple sources.

I created this project after searching for an updated list of malicious Chrome extensions and finding that most resources were outdated or incomplete. I'm committed to keeping this database alive and current through automated monitoring and community contributions.
  
## 📊 Statistics

The database is updated daily if new malicious extensions are discovered.

![Last Updated](https://img.shields.io/badge/Last%20Updated-2026--02--04-blue)



![Last Updated](https://img.shields.io/badge/Total%20Extensions-369-red)


## 📰 Recent Security News

- **2026-01-30**:[Researchers Uncover Chrome Extensions Abusing Affiliate Links and Stealing ChatGPT Access](https://thehackernews.com/2026/01/researchers-uncover-chrome-extensions.html)
- **2026-01-28**: [Malicious Chrome extensions can spy on your ChatGPT chats](https://www.malwarebytes.com/blog/news/2026/01/malicious-chrome-extensions-can-spy-on-your-chatgpt-chats)
- **2026-01-27**: [Small Tools, Big Risk: When Browser Extensions Start Stealing API Keys](https://www.obsidiansecurity.com/blog/small-tools-big-risk-when-browser-extensions-start-stealing-api-keys)
- **2026-01-27**: [Stanley — A $6,000 Russian Malware Toolkit with Chrome Web Store Guarantee](https://www.varonis.com/blog/stanley-malware-kit)
- **2026-01-27**: [Malicious Chrome Extension Performs Hidden Affiliate Hijacking](https://socket.dev/blog/malicious-chrome-extension-performs-hidden-affiliate-hijacking)
- **2026-01-26**: [How We Discovered A Campaign of 16 Malicious Extensions Built to Steal ChatGPT Accounts](https://layerxsecurity.com/blog/how-we-discovered-a-campaign-of-16-malicious-extensions-chatgpt/)
- **2026-01-26**: [Chrome Extensions: Are you getting more than you bargained for?](https://www.security.com/threat-intelligence/chrome-extensions-are-you-getting-more-you-bargained)
- **2025-12-24**: [Silent Takeover: How Purchased Chrome Extensions Became Remote-Controlled Webpage Manipulation Tools](https://layerxsecurity.com/blog/silent-takeover-how-purchased-chrome-extensions-became-remote-controlled-webpage-manipulation-tools/)
- **2025-12-15**: [8 Million Users' AI Conversations Sold for Profit by "Privacy" Extensions](https://www.koi.ai/blog/urban-vpn-browser-extension-ai-conversations-data-collection)

## Data Sources


The database is automatically updated by aggregating information from:

- Chrome extension monitoring services
- Security research blogs and publications
- Threat intelligence feeds

## Database Structure

Each extension entry includes:

- **Extension ID** - Unique Chrome Web Store identifier
- **Name** - Extension name
- **Date Added** - When the extension was added to this database


## Usage


This database is intended for:
- Security research
- Extension vetting and analysis
- Building protective tools
- Threat intelligence

## Tools

**Coming Soon:** A Python tool for macOS that pulls the CSV list and checks for malicious extensions installed on your device.

## Data Format

Data is available in multiple formats:

- .md
- .csv

## Contributing

If you're aware of a malicious extension that should be included, please open an issue with:

- Extension ID
- Evidence or source of malicious behavior
- Date of discovery/removal

## Disclaimer

This database is provided for research and educational purposes. The information is aggregated from public sources and automated monitoring. While efforts are made to ensure accuracy, false positives may occur. Always verify findings before taking action.
