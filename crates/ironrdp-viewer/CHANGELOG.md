# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Changed

- `--graphics-upgrade` now accepts `1|2` (was `1|2|3`). The third progressive
  `TILE_UPGRADE` decode variant was removed as incompatible with the current
  `ironrdp-graphics` base-quantization pipeline (see that crate's CHANGELOG).


## [[0.1.0](https://github.com/Devolutions/IronRDP/releases/tag/ironrdp-viewer-v0.1.0)] - 2026-07-10

Initial release.
