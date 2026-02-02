# Malicious Chrome Extensions Database

An automatically updated database of malicious Chrome extensions removed from the Chrome Web Store.

## Overview

This repository maintains a current list of Chrome extensions that have been removed for malware, security violations, or malicious behavior. Since no regularly-updated public database exists for this purpose, this project automates the collection and aggregation of extension removals from multiple sources.

I created this project after searching for an updated list of malicious Chrome extensions and finding that most resources were outdated or incomplete. I'm committed to keeping this database alive and current through automated monitoring and community contributions.

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

## Updates

The database is updated daily if new malicious extensions are discovered.

**Last Updated:** **2026-02-02**

**Total Extensions:** **314**

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