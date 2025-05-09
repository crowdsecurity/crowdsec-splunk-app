# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## SemVer public API

The [public API](https://semver.org/spec/v2.0.0.html#spec-item-1) of this library consists of all code related to the
Splunk app: i.e. all files and folders except ones that are ignored by the `.slimignore` file.


---

## [1.2.0](https://github.com/crowdsecurity/crowdsec-splunk-app/releases/tag/v1.2.0) - 2025-05-??

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
