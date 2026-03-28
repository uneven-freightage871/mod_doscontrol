# Changelog

All notable changes to this project will be documented in this file.

Version format:
MAJOR.MINOR.PATCH [YYYY.MMDD]

---

## 1.0.0 [2026.0328] @ BuriXon-code

### Added
- Initial release of `mod_doscontrol`
- Apache 2.4 module for detecting abusive traffic and early DoS patterns
- Per-IP request tracking (hash table based)
- Per-URI (page-level) detection
- Per-site request rate detection
- Configurable detection intervals and thresholds
- Configurable blocking period
- Configurable response codes (403 / 429)
- Optional response delay (`DOSBlockDelay`)
- IP whitelist (exact, wildcard, CIDR)
- User-Agent whitelist (wildcard)
- URI-based custom detection levels (`DOSCustomLevel`)
- Structured logging system
- File-based incident cache
- Email notifications
- External command execution on detection
- Support for global and VirtualHost configuration

### Changed
- Refactored architecture based on `mod_evasive`
- Improved configuration handling and merging logic
- Cleaner separation of detection, logging, and execution paths

### Notes
- First release
- Focus on detection, logging, and extensibility

### TODO / Issues
- Improve code comments for readability and user customization/changeability
- Add infinite (dynamic) quantity and parsing `DOSCustomLevel`

---

## [Unreleased]

- Work in progress
