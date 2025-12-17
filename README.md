# Linux Server Auditor

A comprehensive security auditing tool for Linux servers that evaluates system configurations against industry best practices and NIST cybersecurity standards.

## 🚀 Features

- **8 Core Audit Modules**: System, Users, Files, Services, Network, Security, Logs, Cron, SSH
- **Multi-Format Reporting**: HTML and TXT output with visualizations
- **Intelligent Scoring**: A-D grading system with weighted scoring
- **Cross-Platform Support**: Ubuntu, Debian, CentOS, RHEL compatibility
- **Extensible Architecture**: Plugin-based design for easy customization
- **Comprehensive Logging**: Detailed audit trails and error tracking

## 📋 Requirements

- **Operating System**: Linux (Ubuntu 18.04+, CentOS 7+, Debian 9+, RHEL 7+)
- **Python**: 3.8 or higher
- **Permissions**: Root access required for comprehensive auditing

## 🛠️ Installation

### Prerequisites

```bash
# Update package manager
sudo apt update && sudo apt upgrade -y  # Ubuntu/Debian
# OR
sudo yum update -y  # CentOS/RHEL

# Install Python 3.8+ (if not already installed)
sudo apt install python3.8 python3-pip -y  # Ubuntu/Debian
# OR
sudo yum install python38 python38-pip -y  # CentOS/RHEL
```

### Clone and Install

```bash
# Clone the repository
git clone https://github.com/yourusername/linux-server-auditor.git
cd linux-server-auditor

# Install Python dependencies
pip3 install -r requirements.txt

# Make the script executable
chmod +x main.py
```

### Dependencies

The tool requires several system commands for full functionality:

```bash
# Ubuntu/Debian
sudo apt install sudo lastlog ss -y

# CentOS/RHEL
sudo yum install sudo lastlog iproute -y
```

## 📖 Usage

### Basic Usage

```bash
# Run all audit modules
sudo python3 main.py

# Run specific modules only
sudo python3 main.py --modules system,users,security

# Generate HTML report
sudo python3 main.py --output html --report-dir ./reports

# Quick security check (critical issues only)
sudo python3 main.py --quick

# Check specific compliance framework
sudo python3 main.py --compliance nist
```

### Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--modules` | Comma-separated list of modules | `--modules system,users,files` |
| `--exclude` | Modules to exclude | `--exclude logs,cron` |
| `--output` | Output format (html, txt, json) | `--output html` |
| `--report-dir` | Directory for reports | `--report-dir ./reports` |
| `--severity` | Minimum severity level | `--severity high` |
| `--compliance` | Compliance framework | `--compliance nist` |
| `--verbose` | Enable verbose logging | `--verbose` |
| `--config` | Custom configuration file | `--config custom.json` |

### Example Output

```
====================================================================
                    LINUX SERVER SECURITY AUDIT
====================================================================

Server Information:
- Hostname: server01.example.com
- OS: Ubuntu 20.04.3 LTS
- Kernel: 5.14.0-3.0.3.kwai.x86_64
- Audit Date: 2025-12-17 12:00:00

OVERALL SECURITY SCORE: B (82%)

Module Breakdown:
- System: A (92%)
- Users: B (85%)
- Files: C (73%)
- Services: A (90%)
- Network: B (81%)
- Security: A (95%)
- Logs: B (84%)
- Cron: C (76%)
- SSH: A (91%)

CRITICAL ISSUES (4):
1. World-writable file detected: /tmp/sensitive_data
2. Weak SSH cipher suite configured
3. Outdated kernel version (CVE-2023-12345)
4. Inactive user accounts not removed

[Detailed results follow...]
```

## 📊 Audit Modules

### 1. System Module
- Kernel version and security patches
- System uptime and load
- Memory usage and swap configuration
- Disk space and partitioning
- System services status
- Boot configuration security
- System update status

### 2. Users & Groups Module ⭐ **NEW**
- User account enumeration and analysis
- Password policy compliance checking
- Account lockout and expiration detection
- Sudo configuration auditing
- SSH access analysis and key strength validation
- Privilege escalation risk assessment
- Duplicate UID/GID detection
- Inactive and expired account identification

### 3. Files Module
- Critical file permissions (700, 600, 644 standards)
- World-writable file detection
- SUID/SGID file enumeration
- File system mount options
- Disk encryption status
- Backup configuration

### 4. Services Module
- Service enumeration (systemd, init)
- Unnecessary service detection
- Service configuration review
- Port and protocol analysis
- Service dependency validation
- Auto-start configuration

### 5. Network Module
- Network interface configuration
- Firewall rule analysis (iptables, firewalld)
- Routing table security
- DNS configuration
- Network service exposure
- VPN configuration

### 6. Security Module
- SELinux/AppArmor status
- Auditd configuration
- Fail2ban setup
- Intrusion detection systems
- Security patches status
- Vulnerability scanning integration

### 7. Logs Module
- Log rotation configuration
- Log file permissions
- Centralized logging setup
- Log integrity monitoring
- Log retention policies
- Log analysis tools

### 8. Cron Module
- Cron job enumeration
- Cron file permissions
- Suspicious schedule detection
- User cron access control
- System cron configuration
- Anacron security

### 9. SSH Module
- SSH daemon configuration
- Key-based authentication setup
- Protocol version enforcement
- Cipher suite validation
- Port configuration
- Access control lists

## 🎯 Compliance Frameworks

The auditor supports multiple compliance frameworks:

- **NIST Cybersecurity Framework**: Complete alignment with NIST controls
- **CIS Benchmarks**: Configuration best practices
- **Custom Frameworks**: User-defined compliance rules

## 📈 Scoring System

### Grade Scale
- **A Grade**: 90-100% - Excellent security posture
- **B Grade**: 80-89% - Good security with minor issues
- **C Grade**: 70-79% - Moderate security concerns
- **D Grade**: 60-69% - Significant security issues
- **F Grade**: <60% - Critical security problems

### Weighted Scoring
Each module contributes to the overall score based on security importance:

| Module | Weight |
|--------|--------|
| Security | 1.5 |
| SSH | 1.3 |
| Users | 1.2 |
| System | 1.1 |
| Network | 1.0 |
| Services | 0.9 |
| Files | 0.8 |
| Logs | 0.7 |
| Cron | 0.6 |

## 🗂️ Report Formats

### HTML Report
Interactive dashboard with:
- Score visualization and gauges
- Expandable check details
- Security trend charts
- Compliance mapping matrix
- Executive summary
- Technical recommendations

### Text Report
Console-friendly format with:
- Summary statistics
- Critical issues highlighted
- Check-by-check results
- Compliance summary

### JSON Report
Machine-readable format for:
- Integration with other tools
- Automated processing
- Custom reporting

## 🔧 Configuration

### Default Configuration

The tool uses `config/default_config.json` for default settings:

```json
{
    "modules": {
        "enabled": ["system", "users", "files", "services", "network", "security", "logs", "cron", "ssh"],
        "timeout": 300,
        "parallel_execution": true
    },
    "scoring": {
        "module_weights": {
            "security": 1.5,
            "ssh": 1.3,
            "users": 1.2,
            "system": 1.1,
            "network": 1.0,
            "services": 0.9,
            "files": 0.8,
            "logs": 0.7,
            "cron": 0.6
        }
    },
    "output": {
        "formats": ["html", "txt"],
        "report_dir": "./reports",
        "include_details": true,
        "include_recommendations": true
    }
}
```

### Custom Configuration

Create a custom config file and specify it with `--config`:

```bash
sudo python3 main.py --config /path/to/custom.json
```

## 🚨 Security Considerations

### Privilege Requirements
- **Root Access**: Required for comprehensive system auditing
- **Sudo Usage**: Controlled elevation for specific operations
- **Credential Handling**: Secure temporary credential storage
- **Access Control**: Proper file and directory permissions

### Data Protection
- **Sensitive Data**: Avoids logging passwords and keys
- **Temporary Files**: Secure temporary file handling
- **Memory Management**: Clears sensitive data from memory
- **Output Sanitization**: Prevents information leakage

## 🐛 Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   ```bash
   # Ensure you're running as root
   sudo python3 main.py
   
   # Check file permissions
   sudo chmod +x main.py
   ```

2. **Missing Dependencies**
   ```bash
   # Install Python dependencies
   pip3 install -r requirements.txt
   
   # Install system dependencies
   sudo apt install sudo lastlog ss -y  # Ubuntu/Debian
   ```

3. **Module Execution Failures**
   ```bash
   # Run with verbose logging
   sudo python3 main.py --verbose
   
   # Check specific module
   sudo python3 main.py --modules users --verbose
   ```

### Log Files
- **Application Logs**: `./logs/auditor.log`
- **Audit Trail**: Embedded in reports
- **Error Details**: Console output with `--verbose`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Update documentation
6. Submit a pull request

### Module Development

To add a new audit module:

1. Create module file in `modules/` directory
2. Inherit from `BaseModule` class
3. Implement required methods:
   - `get_name()`
   - `get_description()`
   - `execute()`
   - `get_version()`
4. Add to module registry in `main.py`

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## �熊️ Authors

- **System Security Architecture Team**
- **Boni Yeamin** - Initial work

## 🙏 Acknowledgments

- NIST for cybersecurity framework guidance
- CIS for benchmark standards
- Open source community for inspiration and dependencies

## 🔗 Related Projects

- [OpenSCAP](https://www.open-scap.org/) - Security compliance automation
- [Lynis](https://cisofy.com/lynis/) - Security auditing tool
- [CIS-CAT Lite](https://www.cisecurity.org/cis-cat/) - Configuration assessment tool

---

**Note**: This tool is designed for authorized security auditing only. Users are responsible for ensuring they have proper authorization before running audits on any system.