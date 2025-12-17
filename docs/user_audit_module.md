# Users & Groups Audit Module Documentation

## Overview

The Users & Groups Audit Module (`user_audit.py`) is a comprehensive security auditing tool that evaluates user account management, authentication, and access controls on Linux systems. It provides detailed analysis of user accounts, group memberships, sudo configuration, SSH access, and various security issues.

## Features

### 1. User Account Enumeration and Analysis
- **Complete User Listing**: Enumerates all user accounts from `/etc/passwd`
- **Detailed User Information**: 
  - Username, UID, GID
  - Home directory and shell
  - GECOS (comment) field
  - Group memberships (primary and supplementary)
- **Password Policy Analysis**: Analyzes password settings from `/etc/shadow`
  - Password last changed
  - Password expiration
  - Account expiration
  - Account lock status

### 2. Privilege Analysis
- **Root User Detection**: Identifies all users with UID 0
- **Sudo Configuration Audit**: 
  - Parses `/etc/sudoers` and `/etc/sudoers.d/*`
  - Identifies users with sudo privileges
  - Detects security issues in sudo configuration
  - Warns about NOPASSWD configurations
- **Group Membership Analysis**: 
  - Identifies admin groups (sudo, wheel, admin)
  - Maps user-to-group relationships
  - Detects duplicate GIDs

### 3. Account Status Monitoring
- **Inactive Account Detection**: 
  - Checks last login times
  - Identifies accounts inactive for configurable periods
  - Configurable threshold (default: 90 days)
- **Expired Account Detection**: 
  - Checks account expiration dates
  - Identifies expired passwords
  - Monitors password age
- **Locked Account Detection**: 
  - Identifies locked accounts
  - Provides recommendations for locked accounts

### 4. SSH Access Analysis
- **SSH Key Management**: 
  - Analyzes authorized_keys files
  - Checks SSH key strength and types
  - Identifies weak cryptographic algorithms
  - Validates key permissions
- **SSH Configuration Security**: 
  - Checks authorized_keys file permissions
  - Validates SSH directory structure
  - Identifies potential SSH security issues

### 5. Security Issue Detection
- **Duplicate UID/GID Detection**: 
  - Identifies users with duplicate UIDs
  - Identifies groups with duplicate GIDs
  - Provides remediation recommendations
- **Default Account Analysis**: 
  - Identifies default system accounts
  - Checks for unnecessary default accounts
- **Password Security**: 
  - Detects empty passwords
  - Identifies weak password configurations
  - Checks password policy compliance

## Implementation Details

### Data Structures

#### UserAccount Class
```python
@dataclass
class UserAccount:
    username: str
    uid: int
    gid: int
    home_dir: str
    shell: str
    gecos: str
    last_login: Optional[datetime] = None
    password_last_changed: Optional[datetime] = None
    password_expires: Optional[datetime] = None
    account_expires: Optional[datetime] = None
    is_locked: bool = False
    groups: List[str] = None
```

#### SSHAccessInfo Class
```python
@dataclass
class SSHAccessInfo:
    user: str
    authorized_keys_file: str
    key_count: int
    keys: List[Dict[str, Any]]
    ssh_config_issues: List[str]
```

### Key Methods

#### 1. `_enumerate_users()`
- Reads `/etc/passwd` using `pwd.getpwall()`
- Gathers user information and group memberships
- Extracts password information from `/etc/shadow` (if accessible)
- Determines last login times using `lastlog` command

#### 2. `_enumerate_groups()`
- Reads `/etc/group` using `grp.getgrall()`
- Maps group names to member lists
- Supports supplementary group analysis

#### 3. `_check_sudo_configuration()`
- Parses `/etc/sudoers` and `/etc/sudoers.d/*` files
- Identifies users with sudo privileges
- Detects security issues:
  - NOPASSWD configurations
  - Unrestricted root access
  - Poorly configured sudo rules

#### 4. `_analyze_ssh_access()`
- Checks for SSH authorized_keys files
- Analyzes SSH key strength and types
- Validates file permissions
- Detects weak cryptographic algorithms

#### 5. `_check_account_status()`
- Checks for inactive accounts (configurable threshold)
- Identifies expired accounts and passwords
- Monitors password age
- Detects locked accounts

#### 6. `_check_security_issues()`
- Detects duplicate UIDs and GIDs
- Identifies empty passwords
- Checks for default system accounts
- Validates multiple root users

## Security Checks

### 1. Privilege Escalation Risks
- **Multiple Root Users**: Warns if more than one user has UID 0
- **Weak Sudo Configuration**: Detects NOPASSWD and unrestricted access
- **Group Membership Issues**: Identifies excessive group memberships

### 2. Authentication Security
- **Password Policy**: Checks password age and expiration
- **Account Lockout**: Identifies locked accounts
- **Empty Passwords**: Detects accounts with no password set

### 3. SSH Security
- **Key Strength**: Validates SSH key cryptographic strength
- **File Permissions**: Checks authorized_keys file permissions
- **Algorithm Security**: Warns about weak SSH algorithms

### 4. Account Management
- **Inactive Accounts**: Identifies unused accounts
- **Expired Accounts**: Detects expired accounts and passwords
- **Default Accounts**: Warns about unnecessary default accounts

## Configuration Options

The module supports configuration through the main configuration system:

```json
{
    "security": {
        "max_inactive_days": 90,
        "max_password_age": 90,
        "min_uid": 1000,
        "check_duplicate_uids": true,
        "check_duplicate_gids": true,
        "require_strong_ssh_keys": true,
        "check_sudo_configuration": true
    }
}
```

## Output Format

### Module Result Structure
```python
ModuleResult(
    status=ModuleStatus.SUCCESS,
    score=85.0,  # Calculated score
    issues=[SecurityIssue(...)],  # List of security issues found
    metadata={
        'total_users': 25,
        'total_groups': 15,
        'root_users_count': 1,
        'sudo_users_count': 3,
        'inactive_users_count': 2,
        'ssh_users_count': 8,
        'user_details': {...},
        'group_details': {...}
    },
    timestamp="2025-12-17T08:00:00"
)
```

### Security Issue Structure
Each security issue includes:
- **Title**: Brief description of the issue
- **Description**: Detailed explanation
- **Severity**: LOW, MEDIUM, HIGH, or CRITICAL
- **Recommendation**: Actionable remediation steps
- **Affected Files**: List of relevant files
- **Evidence**: Supporting evidence
- **CVE ID**: If applicable

## Examples

### Example 1: Multiple Root Users Detection
```
Title: Multiple users with root privileges (UID 0)
Description: Multiple users have UID 0: root, admin
Severity: CRITICAL
Recommendation: Limit root access to minimum necessary accounts
Affected Files: ['/etc/passwd']
Evidence: ['Root users: root, admin']
```

### Example 2: Inactive User Account
```
Title: Inactive user account: olduser
Description: User olduser has not logged in for 180 days
Severity: MEDIUM
Recommendation: Review and disable or remove inactive accounts
Evidence: ['Last login: 2025-06-17 10:30:00']
```

### Example 3: Weak SSH Keys
```
Title: Weak SSH keys for user developer
Description: User developer has 2 weak SSH key(s)
Severity: HIGH
Recommendation: Replace weak SSH keys with stronger ones (RSA 2048+ bits, Ed25519, or ECDSA)
Affected Files: ['/home/developer/.ssh/authorized_keys']
Evidence: ['Weak keys: ['ssh-rsa', 'ssh-rsa']']
```

## Integration with Main Auditor

The module integrates seamlessly with the main auditor system:

1. **Module Registration**: Automatically detected and loaded
2. **Configuration**: Uses centralized configuration system
3. **Scoring**: Contributes to overall security score
4. **Reporting**: Integrated into HTML and text reports
5. **Logging**: Uses centralized logging system

## Performance Considerations

- **Efficient Enumeration**: Uses system calls for fast user/group enumeration
- **Parallel Processing**: Supports parallel execution with other modules
- **Memory Usage**: Minimal memory footprint
- **Execution Time**: Typically completes in 10-30 seconds depending on system size

## Security Considerations

- **Root Access Required**: Needs root privileges for comprehensive auditing
- **Sensitive Data Handling**: Properly handles password and authentication data
- **Audit Trail**: Maintains detailed logs of all operations
- **Error Handling**: Graceful handling of permission and access errors

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   - Ensure running with root privileges
   - Check file permissions on `/etc/passwd`, `/etc/shadow`, `/etc/group`

2. **Missing Dependencies**
   - Verify required commands are available: `lastlog`, `sudo`, `ss`
   - Check Python module availability: `pwd`, `grp`, `subprocess`

3. **SSH Analysis Failures**
   - Check home directory permissions
   - Verify SSH directory structure
   - Ensure authorized_keys files are readable

### Debug Mode
Enable verbose logging for detailed troubleshooting:
```bash
sudo python3 main.py --modules users --verbose
```

## Future Enhancements

Potential improvements for future versions:
- Integration with LDAP/Active Directory
- Real-time monitoring capabilities
- Advanced anomaly detection
- Integration with SIEM systems
- Custom security policy definitions
- Historical trend analysis