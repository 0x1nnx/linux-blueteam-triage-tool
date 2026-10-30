# Linux Blue Team Triage Tool

A Bash-based Linux security auditing and host triage tool designed to assist Blue Team operations, system administrators, and cybersecurity enthusiasts with identifying potentially suspicious system activity.

The tool collects system, network, authentication, process, persistence, and security configuration information and generates a timestamped report for further investigation.

## Features

### 1. System Information
- Hostname and operating system identification
- Kernel information
- System uptime and load
- CPU and memory information
- Disk usage and block devices
- Running processes
- Active system services

### 2. Network Auditing
- Network interface and IP address enumeration
- Routing table inspection
- Listening ports and network sockets
- Established network connections
- ARP and neighbor table inspection
- DNS configuration
- Firewall status and rules

### 3. User and Authentication Auditing
- Logged-in users and active sessions
- Local user account enumeration
- UID 0 account identification
- Accounts with interactive login shells
- Password aging information
- Successful login history
- Failed login attempts

### 4. SSH Security Auditing
- SSH service status
- SSH server configuration inspection
- SSH configuration drop-in files
- Authorized SSH key enumeration

### 5. Persistence Mechanism Auditing
- Enabled systemd services
- Systemd timers
- System-wide cron jobs
- User crontabs
- Shell startup scripts
- User initialization files

### 6. Process Investigation
- Running process enumeration
- Process tree visualization
- Detection of processes with deleted executables
- Network-listening processes
- Open files in temporary directories

### 7. Filesystem Triage
- Recently modified files in temporary directories
- World-writable files in temporary locations
- SUID file enumeration
- SGID file enumeration

### 8. Security Controls
- Loaded kernel modules
- SELinux status
- AppArmor status
- Address Space Layout Randomization (ASLR) configuration
- Secure Boot status

### 9. Security Log Collection
- SSH authentication events
- Failed authentication attempts
- Invalid user attempts
- Successful SSH authentication events
- Sudo-related events
- Kernel messages

### 10. Package and Container Auditing
- Installed package enumeration
- Docker container enumeration
- Podman container enumeration

### 11. Hardware Health
- Hardware sensor information
- SMART disk health status
- BIOS information
- GPU identification

### 12. Report Generation
- Timestamped security reports
- Consolidated system and security information
- SHA256 report hashing
- Restrictive file permissions for generated reports

## Requirements

- Linux operating system
- Bash
- systemd (for systemd-related checks)

The following utilities are optional and provide additional information:

| Utility | Purpose |
|---|---|
| `iproute2` | Network inspection |
| `procps` | Process and memory information |
| `util-linux` | System and disk information |
| `lsof` | Open file inspection |
| `pstree` | Process tree visualization |
| `smartmontools` | Disk health checks |
| `lm-sensors` | Hardware sensor information |
| `dmidecode` | BIOS information |
| `pciutils` | GPU identification |
| `nftables` | Firewall inspection |
| `ufw` | Firewall inspection |
| `firewalld` | Firewall inspection |

## Installation

Clone the repository:

```bash
git clone https://github.com/0x1nnx/linux-blueteam-triage.git
```

Navigate into the project directory:

```bash
cd linux-blueteam-triage
```

Make the script executable:

```bash
chmod 750 blueteam.sh
```

## Usage

Run the script:

```bash
sudo ./blueteam.sh
```

Root privileges are recommended to obtain more complete system and security information.

The interactive menu provides access to individual auditing functions and complete report generation.

## Report Generation

Select option 13 from the menu to generate a complete Blue Team triage report.

Example output:

```text
blueteam_hostname_20261030_122000.txt
blueteam_hostname_20261030_122000.txt.sha256
```

The report is saved in the current working directory.

The SHA256 file contains the checksum of the generated report and can be used to verify that the report has not changed since hashing.

## Security Considerations

This tool is designed primarily for read-only system inspection and information collection.

It does not intentionally modify system configurations, create users, change firewall rules, or terminate processes.

However, some commands may interact with system services or require elevated privileges.

Generated reports may contain sensitive information, including:

- Usernames and account information
- Internal and external IP addresses
- Authentication events
- SSH authorized public keys
- Network configuration
- Running processes and services
- Firewall configuration

Store generated reports securely and do not upload them to public repositories.

Only execute this tool on systems you own or are explicitly authorized to investigate.

## Limitations

- Detection results require manual investigation and validation.
- Some checks depend on installed utilities.
- Certain information requires root privileges.
- Recently modified files and unusual processes are not necessarily malicious.
- The tool does not replace a dedicated EDR, SIEM, or forensic acquisition solution.
- The collector does not guarantee complete forensic evidence preservation.

## Future Improvements

Planned enhancements include:

- Automated suspicious activity detection
- SSH brute-force attempt detection
- Detection of unexpected privileged accounts
- Suspicious systemd service identification
- Cron persistence detection
- Baseline comparison and file integrity monitoring
- Improved JSON report generation
- Centralized log analysis
- Integration with SIEM platforms
- Automated security findings and severity classification
- Automated ShellCheck and testing through GitHub Actions

## Project Structure

```text
linux-blueteam-triage/
├── blueteam.sh
├── README.md
├── LICENSE
├── .gitignore
└── docs/
```

## Disclaimer

This project is intended for educational, defensive cybersecurity, Linux system administration, and authorized security auditing purposes.

The author is not responsible for misuse or damage resulting from unauthorized execution.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Author

Developed as a Linux Blue Team and cybersecurity learning project.

GitHub: https://github.com/0x1nnx
