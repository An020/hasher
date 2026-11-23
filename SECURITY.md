# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| `1.x` | Yes |
| `< 1.0` | No |

## Reporting a Vulnerability

Please report security issues privately through GitHub Security Advisories (`Security -> Advisories -> Report a vulnerability`) rather than opening a public issue. Include reproduction steps, sample inputs or manifests, and affected version details.

## Security Design Notes

- **Manifest path safety (`hashcheck -c`)**: Manifest entries are restricted to paths inside the manifest's base directory. Empty paths, `..` traversal, root/drive prefixes, UNC network paths (`\\server\share`), Windows device paths (`\\.\...`), and symlinks resolving outside the base directory are rejected.
- **Clipboard inspection (`hashcheck -i`)**: Clipboard UNC and device paths (`\\...`, `//...`) are ignored before filesystem checks to avoid unintended SMB connections or device stalls.
- **GUI launcher (`hashcheck --gui`)**: Launches only the sibling `hasher.exe` beside the running `hashcheck` executable instead of searching the current working directory.
- **Release verification**: Verify downloaded release archives against the published `.sha256` checksum asset before extracting or running binaries.
