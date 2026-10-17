# Data License

## Creative Commons Attribution 4.0 International (CC BY 4.0)

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)

Copyright (c) 2026 toborrm9

The data files listed below are licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0).

Code in this repository is licensed separately under the MIT License. See `LICENSE.md` below.

This license applies to versions of the data files published on or after 17 October 2026. Versions published before that date remain available under the MIT License.

---

## Summary

You are free to:

- **Share:** copy and redistribute the data in any medium or format.
- **Adapt:** remix, transform, and build upon the data for any purpose, including commercially.

Under the following terms:

- **Attribution:** you must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.
- **No additional restrictions:** you may not apply legal terms or technological measures that legally restrict others from doing anything the license permits.

This summary is not a substitute for the legal code. Only the full license text is legally binding.

---

## How to Attribute

Use the following credit when you use this data in a project, product, feed, or publication:

> Extension IOC data from malext.io (malicious_extension_sentry), licensed under CC BY 4.0.
> https://github.com/toborrm9/malicious_extension_sentry

If you modified, filtered, or merged the data, add "Modified from" before the credit.

For commercial products and services, a credit in your documentation, about page, data sources page, or acknowledgements section is sufficient.

---

## What This Covers

This license applies to the following data files:

| File | Description |
| ---- | ----------- |
| `malicious_extensions_detailed.csv` | Primary IOC dataset: extension ID, name, reason, source, date, blocklist status, store, version, SHA-256 |
| `Malicious-Extensions.csv` | Simplified list of extension IDs |
| `Malicious-Extensions.md` | Markdown table view of the dataset |
| `threat-intel-feeds/malext_feed.json` | JSON feed |
| `threat-intel-feeds/malext_stix2_bundle.json` | STIX 2.1 bundle |
| `threat-intel-feeds/malext_misp_event.json` | MISP event |
| `threat-intel-feeds/malext_misp_warninglist.json` | MISP warninglist |
| `threat-intel-feeds/malext_opencti_indicators.csv` | OpenCTI indicators |
| `threat-intel-feeds/malext_splunk_lookup.csv` | Splunk lookup table |

---

## What This Does Not Cover

- **Code:** `malext.py` is licensed under the MIT License. See `LICENSE.md`.
- **Threat reports:** files in `findings/` are not covered by this license. All rights reserved unless a report states otherwise.
- **Website and project files:** `README.md`, `CHANGELOG.md`, `privacy.html`, and `CNAME`.
- **Third-party content:** research, articles, and reports linked in the `source` field belong to their respective authors and publishers. This license covers the link and the indicator, not the linked content. Respect each source's own license when reproducing its content.
- **Trademarks:** the malext.io name and logo are not licensed under CC BY 4.0.

---

## No Warranty

This data is provided "as is", without warranty of any kind, express or implied.

Entries are compiled from automated store monitoring, original research, and public third-party reporting. The data may contain false positives, outdated entries, or errors. An entry means an extension was flagged or removed for a stated reason. It is not a legal finding against its developer.

Validate entries before using them for automated blocking, removal, or enforcement decisions. The licensor is not liable for any damages arising from use of this data.

---

## Corrections and Removal Requests

If you believe an entry is incorrect, report it here https://malext.io/report with the extension ID and supporting evidence. Valid corrections will be applied in the next update.

---

## Full License Text

The full legal code of CC BY 4.0 is available at:
https://creativecommons.org/licenses/by/4.0/legalcode

---

## Contact

Questions, corrections, or feed and partnership inquiries:
https://github.com/toborrm9/malicious_extension_sentry/issues



---

## MIT License (Code)

Applies to: `malext.py`

Copyright (c) 2026 toborrm9

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
