# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## SemVer public API

The [public API](https://semver.org/spec/v2.0.0.html#spec-item-1) of this library consists of all code related to the
Splunk app: i.e., all files and folders except ones that are ignored by the `.slimignore` file.

---

## [1.2.4](https://github.com/crowdsecurity/crowdsec-splunk-app/releases/tag/v1.2.4) - 2025-11-25

[_Compare with previous release_](https://github.com/crowdsecurity/crowdsec-splunk-app/compare/v1.2.2...v1.2.4)

### Changed

- Fix fields not being present in the records if the first match was an unknown IP or without an IP field
- Force app to run on the search head.

## [1.2.2](https://github.com/crowdsecurity/crowdsec-splunk-app/releases/tag/v1.2.2) - 2025-11-17

[_Compare with previous release_](https://github.com/crowdsecurity/crowdsec-splunk-app/compare/v1.2.1...v1.2.2)

### Changed

- Improve retrieval/display of existing settings
- Always use the name of the field(s) in the output variable name, allowing enrichment of events containing multiple IPs

### Added

- Add a `fields` argument allowing to select relevant fields (i.e. `ipfield="ip" fields="reputation,confidence"`)
- Support batching to API

---

## [1.2.1](https://github.com/crowdsecurity/crowdsec-splunk-app/releases/tag/v1.2.1) - 2025-06-27

[_Compare with previous release_](https://github.com/crowdsecurity/crowdsec-splunk-app/compare/v1.2.0...v1.2.1)

### Fixed

- Make API key editable in the UI

---

## [1.2.0](https://github.com/crowdsecurity/crowdsec-splunk-app/releases/tag/v1.2.0) - 2025-05-16

[_Compare with previous release_](https://github.com/crowdsecurity/crowdsec-splunk-app/compare/v1.1.1...v1.2.0)

### Added

- Add missing CTI fields (`reputation`, `confidence`, `mitre_techniques`, `cves`, `background_noise`, `ip_range_24`, `ip_range_24_reputation`, `ip_range_24_score`)

### Fixed

- Fix typo for `aggressiveness` fields

---

## [1.1.1](https://github.com/crowdsecurity/crowdsec-splunk-app/releases/tag/v1.1.1) - 2025-04-21

[_Compare with previous release_](https://github.com/crowdsecurity/crowdsec-splunk-app/compare/v1.1.0...v1.1.1)

### Fixed

- Fix Splunk compatible versions list

---

## [1.1.0](https://github.com/crowdsecurity/crowdsec-splunk-app/releases/tag/v1.1.0) - 2025-04-18

[_Compare with previous release_](https://github.com/crowdsecurity/crowdsec-splunk-app/compare/v1.0.6...v1.1.0)

### Changed

- Update Splunk Python SDK sources

---

## [1.0.6](https://github.com/crowdsecurity/crowdsec-splunk-app/releases/tag/v1.0.6) - 2023-03-22

- Initial release
