# Security Policy

## Reporting Vulnerabilities

If you discover security issues, please do not use public bug trackers. Send reports directly to: [@ingeniare](https://github.com/ingeniare)

## Security Architecture

This implementation is based on the following principles and technical measures:

### Privilege Separation
The MTProxy service runs under a dedicated system account `mtproxy` with no login shell and no home directory. This minimizes risk in case of service compromise.

### Credential Isolation
Operational secrets are stored in `/etc/mtproxy/secret` with `0600` permissions (read/write for owner only). This prevents key leakage through systemd diagnostics or unit configuration files. Per-user secrets are stored in `/etc/mtproxy/secrets.d/` with the same permissions.

### Protocol Obfuscation (Fake TLS)
To counter Deep Packet Inspection (DPI) and heuristic identification systems, Fake TLS transport is supported. Using `ee`-format secrets and the `--domain` parameter, traffic is encapsulated to mimic a standard TLS handshake with trusted domains. The installer auto-selects a plausible domain by verifying DNS resolution and TLS 1.3 support.

### Automated Protection (Rate-Limiting)
The installer configures `iptables` rules using the `hashlimit` module. This limits the rate of new TCP sessions per source IP, reducing server visibility to automated scanning and censorship systems.

### Configuration Integrity Control
The automatic Telegram config update process includes a validation step. Downloaded resources are checked for minimum size and structural correctness before being applied. On update failure, the system preserves the last stable configuration.

### Network Resilience
External IP detection uses a cascade of 8 independent sources. Firewall rule persistence across reboots is ensured via `netfilter-persistent` integration.

## Operational Recommendations

1.  **Authentication**: Use SSH key-based access and disable password login.
2.  **Monitoring**: Regularly check service logs via `journalctl -u MTProxy` for anomalous connection patterns.
3.  **Host Protection**: Install `fail2ban` to protect the SSH management interface from brute-force attacks.
4.  **Updates**: Apply security patches for the base OS in a timely manner.
5.  **Domain Selection**: In production, consider using custom or specific domains for Fake TLS emulation.
6.  **Stats Access**: The statistics web interface is accessible only via loopback (`localhost`). Do not expose this port to external networks.
