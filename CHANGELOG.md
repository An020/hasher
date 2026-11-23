# Changelog

## [1.0.1] - 2026-11-23

### Features

* Add Tab 2 `Batch Check` GUI, multi-GB streaming pipeline, and dynamic `Save Hash` / `Save Hashes` export with `.txt` fallback prompts.

### Security

* Guard `hashcheck` manifest checking and clipboard probing against traversal, drive/UNC/device paths, and CWD GUI binary hijacking, and patch `url` (`RUSTSEC-2026-0592`).

## 1.0.0 (2026-11-23)


### Features

* fast hash verifier with CLI, GUI, and Explorer integration ([0d1d4a3](https://github.com/An020/hasher/commit/0d1d4a36e2c58479649e43e6c87a379c34fe6a98))
