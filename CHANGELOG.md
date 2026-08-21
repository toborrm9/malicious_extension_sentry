# Changelog

Schema and format changes to the MalExt Sentry database.
Data additions happen continuously and are not logged here.

## 2026-08-22

### Added
- `version` column: the extension version string as last seen in the
  Chrome Web Store before removal. Empty when unknown.
- `sha256` column: SHA-256 of the CRX package for that version.
  Empty when the package could not be retrieved.

### Notes
- Both columns are appended at the end of the CSV header. Parsers that
  read by column name are unaffected. Parsers that read by index and
  assume a fixed column count will need updating.
- One row still equals one extension ID.
