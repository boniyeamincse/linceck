"""
Users & Groups Audit Module for Linux Server Auditor

This module audits user account management, authentication, and access controls
including user enumeration, password policies, sudo configuration, and privilege analysis.

Compliance: NIST AC-2 (Account Management), IA-5 (Authenticator Management)
"""

import os
import re
import json
import yaml
import subprocess
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from pathlib import Path
from dataclasses import dataclass, asdict

# Import Unix-specific modules (Linux/Unix only)
import pwd
import grp

from core.base_module import BaseModule, SecurityIssue, ModuleResult, ModuleStatus, SeverityLevel
from core.logger import get_logger
from utils.helpers import SystemUtils, FileUtils, CommandUtils, SecurityUtils, TimeUtils


@dataclass
class UserAccount:
    """User account information structure."""
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


@dataclass
class SSHAccessInfo:
    """SSH access information structure."""
    user: str
    authorized_keys_file: str
    key_count: int
    keys: List[Dict[str, Any]]
    ssh_config_issues: List[str]


class UserAuditModule(BaseModule):
    """
    Users & Groups Audit Module
    
    Audits user account management, authentication, and access controls.
    """
    
    def __init__(self, config):
        """
        Initialize the User Audit Module.
        
        Args:
            config: Configuration object
        """
        super().__init__(config)
        self.users = []  # List of UserAccount objects
        self.groups = {}  # Group name -> members
        self.sudo_users = set()  # Users with sudo privileges
        self.root_users = set()  # Users with UID 0
        self.inactive_users = []  # Inactive user accounts
        self.ssh_access = {}  # SSH access information
        self.security_issues = []
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        
    @property
    def module_name(self) -> str:
        """Return the module name."""
        return "Users & Groups"
    
    @property
    def description(self) -> str:
        """Return a brief description of what this module audits."""
        return "Audits user account management, authentication, password policies, sudo configuration, and SSH access controls"
    
    @property
    def version(self) -> str:
        """Return the module version."""
        return "1.0.0"
    
    def require_root(self) -> bool:
        """
        Check if the module requires root privileges.
        
        Returns:
            True if root is required, False otherwise
        """
        return True
    
    def check_dependencies(self) -> bool:
        """
        Check if required dependencies and permissions are available.
        
        Returns:
            True if dependencies are met, False otherwise
        """
        try:
            # Check if we can access user and group files
            if not os.path.exists('/etc/passwd'):
                self.log_error("Cannot access /etc/passwd file")
                return False
            
            if not os.path.exists('/etc/group'):
                self.log_error("Cannot access /etc/group file")
                return False
            
            # Check if we can read shadow file (requires root)
            if not os.access('/etc/shadow', os.R_OK):
                self.log_warning("Cannot read /etc/shadow file - some password checks will be skipped")
                # Continue without shadow access
            
            # Check for required commands
            required_commands = ['last', 'lastlog', 'sudo', 'ss']
            for cmd in required_commands:
                if not CommandUtils.check_command_exists(cmd):
                    self.log_warning(f"Command '{cmd}' not found - some checks may be limited")
            
            self.log_debug("User audit dependencies check passed")
            return True
            
        except Exception as e:
            self.log_error(f"Dependency check failed: {str(e)}")
            return False
    
    def run(self) -> ModuleResult:
        """
        Execute the user and groups audit.
        
        Returns:
            ModuleResult containing the audit results
        """
        self.log_info("Starting user and groups audit")
        
        try:
            # Gather user and group information
            self._enumerate_users()
            self._enumerate_groups()
            self._check_sudo_configuration()
            self._analyze_ssh_access()
            self._check_account_status()
            self._check_security_issues()
            
            # Calculate score
            score = self.calculate_score_from_issues(self.security_issues, 100.0)
            
            # Prepare metadata
            metadata = {
                'total_users': len(self.users),
                'total_groups': len(self.groups),
                'root_users_count': len(self.root_users),
                'sudo_users_count': len(self.sudo_users),
                'inactive_users_count': len(self.inactive_users),
                'ssh_users_count': len(self.ssh_access),
                'audit_timestamp': self.format_timestamp(),
                'user_details': self._get_user_summary(),
                'group_details': self._get_group_summary()
            }
            
            self.log_info(f"User and groups audit completed with score: {score}")
            
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                score=score,
                issues=self.security_issues,
                metadata=metadata,
                timestamp=self.format_timestamp()
            )
            
        except Exception as e:
            self.log_error(f"User and groups audit failed: {str(e)}")
            import traceback
            self.log_debug(f"Traceback: {traceback.format_exc()}")
            
            return ModuleResult(
                status=ModuleStatus.ERROR,
                score=0.0,
                issues=[],
                metadata={},
                timestamp=self.format_timestamp(),
                error_message=str(e)
            )
    
    def _enumerate_users(self):
        """Enumerate all user accounts and gather detailed information."""
        self.log_debug("Enumerating user accounts")
        
        try:
            # Get all users from /etc/passwd
            for user_info in pwd.getpwall():
                user = UserAccount(
                    username=user_info.pw_name,
                    uid=user_info.pw_uid,
                    gid=user_info.pw_gid,
                    home_dir=user_info.pw_dir,
                    shell=user_info.pw_shell,
                    gecos=user_info.pw_gecos,
                    groups=[]
                )
                
                # Get group memberships
                user.groups = self._get_user_groups(user.username)
                
                # Get password information from /etc/shadow if accessible
                if os.access('/etc/shadow', os.R_OK):
                    self._get_password_info(user)
                
                # Get last login information
                self._get_last_login(user)
                
                # Check if user has UID 0 (root)
                if user.uid == 0:
                    self.root_users.add(user.username)
                
                self.users.append(user)
            
            self.log_debug(f"Enumerated {len(self.users)} user accounts")
            
        except Exception as e:
            self.log_error(f"Failed to enumerate users: {str(e)}")
            self.security_issues.append(
                self.create_issue(
                    title="User Enumeration Failed",
                    description=f"Unable to enumerate user accounts: {str(e)}",
                    severity=SeverityLevel.HIGH,
                    recommendation="Check system permissions and ensure /etc/passwd is accessible",
                    affected_files=['/etc/passwd', '/etc/shadow'],
                    evidence=[f"Error: {str(e)}"]
                )
            )
    
    def _enumerate_groups(self):
        """Enumerate all groups and their members."""
        self.log_debug("Enumerating groups")
        
        try:
            # Get all groups from /etc/group
            for group_info in grp.getgrall():
                group_name = group_info.gr_name
                members = group_info.gr_mem
                self.groups[group_name] = members
            
            self.log_debug(f"Enumerated {len(self.groups)} groups")
            
        except Exception as e:
            self.log_error(f"Failed to enumerate groups: {str(e)}")
            self.security_issues.append(
                self.create_issue(
                    title="Group Enumeration Failed",
                    description=f"Unable to enumerate groups: {str(e)}",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Check system permissions and ensure /etc/group is accessible",
                    affected_files=['/etc/group'],
                    evidence=[f"Error: {str(e)}"]
                )
            )
    
    def _get_user_groups(self, username: str) -> List[str]:
        """Get all groups a user belongs to."""
        try:
            # Get primary group
            primary_group = grp.getgrgid(pwd.getpwnam(username).pw_gid).gr_name
            
            # Get supplementary groups
            supplementary_groups = [g.gr_name for g in grp.getgrall() if username in g.gr_mem]
            
            all_groups = [primary_group] + supplementary_groups
            return list(set(all_groups))  # Remove duplicates
            
        except Exception:
            return []
    
    def _get_password_info(self, user: UserAccount):
        """Get password information from /etc/shadow."""
        try:
            with open('/etc/shadow', 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 8 and parts[0] == user.username:
                        # Parse shadow fields
                        password_hash = parts[1]
                        last_change = parts[2]
                        min_age = parts[3]
                        max_age = parts[4]
                        warning = parts[5]
                        inactive = parts[6]
                        expire = parts[7]
                        
                        # Check if account is locked (password starts with ! or *)
                        user.is_locked = password_hash.startswith(('!', '*'))
                        
                        # Parse dates (days since epoch)
                        if last_change and last_change != '0':
                            try:
                                epoch = datetime(1970, 1, 1)
                                user.password_last_changed = epoch + timedelta(days=int(last_change))
                            except (ValueError, OverflowError):
                                pass
                        
                        if max_age and max_age != '99999':  # 99999 is default (no expiration)
                            try:
                                if user.password_last_changed:
                                    user.password_expires = user.password_last_changed + timedelta(days=int(max_age))
                            except (ValueError, TypeError):
                                pass
                        
                        if expire and expire != '':
                            try:
                                epoch = datetime(1970, 1, 1)
                                user.account_expires = epoch + timedelta(days=int(expire))
                            except (ValueError, OverflowError):
                                pass
                        
                        break
                        
        except Exception as e:
            self.log_debug(f"Could not get password info for {user.username}: {str(e)}")
    
    def _get_last_login(self, user: UserAccount):
        """Get last login information for a user."""
        try:
            # Try to get last login from lastlog
            result = CommandUtils.run_command(['lastlog', '-u', user.username], timeout=10)
            if result['success'] and result['stdout']:
                lines = result['stdout'].strip().split('\n')
                if len(lines) >= 2:  # Header + data
                    login_info = lines[1].split()
                    if len(login_info) >= 4:
                        # Parse lastlog output (date/time format varies)
                        login_str = ' '.join(login_info[3:])
                        try:
                            # Try common date formats
                            for fmt in ['%a %b %d %H:%M:%S %Y', '%Y-%m-%d %H:%M:%S']:
                                try:
                                    user.last_login = datetime.strptime(login_str, fmt)
                                    break
                                except ValueError:
                                    continue
                        except Exception:
                            pass
            
        except Exception as e:
            self.log_debug(f"Could not get last login for {user.username}: {str(e)}")
    
    def _check_sudo_configuration(self):
        """Check sudo configuration and identify users with sudo privileges."""
        self.log_debug("Checking sudo configuration")
        
        try:
            # Check sudoers file
            sudoers_files = ['/etc/sudoers'] + list(Path('/etc/sudoers.d').glob('*'))
            
            for sudoers_file in sudoers_files:
                if not sudoers_file.exists():
                    continue
                
                try:
                    with open(sudoers_file, 'r') as f:
                        content = f.read()
                        self._parse_sudoers(content, str(sudoers_file))
                except Exception as e:
                    self.log_debug(f"Could not read {sudoers_file}: {str(e)}")
            
            # Check for users with wheel/admin group membership
            admin_groups = ['sudo', 'wheel', 'admin']
            for group_name in admin_groups:
                if group_name in self.groups:
                    for user in self.groups[group_name]:
                        self.sudo_users.add(user)
            
            self.log_debug(f"Found {len(self.sudo_users)} users with sudo privileges")
            
        except Exception as e:
            self.log_error(f"Failed to check sudo configuration: {str(e)}")
            self.security_issues.append(
                self.create_issue(
                    title="Sudo Configuration Check Failed",
                    description=f"Unable to check sudo configuration: {str(e)}",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Check sudoers file permissions and syntax",
                    affected_files=['/etc/sudoers'],
                    evidence=[f"Error: {str(e)}"]
                )
            )
    
    def _parse_sudoers(self, content: str, filename: str):
        """Parse sudoers file to identify users with sudo privileges."""
        try:
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Look for user specifications
                if 'ALL=' in line and not line.startswith('Defaults'):
                    parts = line.split()
                    if len(parts) >= 2:
                        user_spec = parts[0]
                        
                        # Handle different user specifications
                        if user_spec.startswith('%'):  # Group
                            group_name = user_spec[1:]
                            if group_name in self.groups:
                                for user in self.groups[group_name]:
                                    self.sudo_users.add(user)
                        elif user_spec == 'ALL':  # All users
                            for user in self.users:
                                self.sudo_users.add(user.username)
                        else:  # Specific user or user alias
                            if ',' in user_spec:
                                users = user_spec.split(',')
                                for user in users:
                                    self.sudo_users.add(user.strip())
                            else:
                                self.sudo_users.add(user_spec)
                
                # Check for problematic configurations
                self._check_sudoers_security(line, filename)
                
        except Exception as e:
            self.log_debug(f"Could not parse sudoers file {filename}: {str(e)}")
    
    def _check_sudoers_security(self, line: str, filename: str):
        """Check sudoers line for security issues."""
        try:
            # Check for NOPASSWD without restrictions
            if 'NOPASSWD:' in line and 'ALL' in line and 'root' not in line:
                self.security_issues.append(
                    self.create_issue(
                        title="Sudo without password authentication",
                        description=f"User/group in {filename} can run commands without password: {line.strip()}",
                        severity=SeverityLevel.HIGH,
                        recommendation="Require password authentication for sudo commands or restrict command access",
                        affected_files=[filename],
                        evidence=[f"Sudoers line: {line.strip()}"]
                    )
                )
            
            # Check for root access without restrictions
            if 'root' in line and 'ALL' in line and 'NOPASSWD:' not in line:
                self.security_issues.append(
                    self.create_issue(
                        title="Unrestricted root access via sudo",
                        description=f"User/group in {filename} has unrestricted root access: {line.strip()}",
                        severity=SeverityLevel.MEDIUM,
                        recommendation="Restrict specific commands that can be run with sudo",
                        affected_files=[filename],
                        evidence=[f"Sudoers line: {line.strip()}"]
                    )
                )
            
        except Exception as e:
            self.log_debug(f"Could not check sudoers security for line: {str(e)}")
    
    def _analyze_ssh_access(self):
        """Analyze SSH access and configuration for users."""
        self.log_debug("Analyzing SSH access")
        
        try:
            for user in self.users:
                if user.shell in ['/bin/false', '/usr/sbin/nologin', '/sbin/nologin']:
                    continue  # Skip system users without shell access
                
                ssh_info = self._get_user_ssh_info(user.username)
                if ssh_info and ssh_info.key_count > 0:
                    self.ssh_access[user.username] = ssh_info
            
            self.log_debug(f"Analyzed SSH access for {len(self.ssh_access)} users")
            
        except Exception as e:
            self.log_error(f"Failed to analyze SSH access: {str(e)}")
            self.security_issues.append(
                self.create_issue(
                    title="SSH Access Analysis Failed",
                    description=f"Unable to analyze SSH access: {str(e)}",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Check SSH configuration and user home directories",
                    affected_files=[],
                    evidence=[f"Error: {str(e)}"]
                )
            )
    
    def _get_user_ssh_info(self, username: str) -> Optional[SSHAccessInfo]:
        """Get SSH access information for a specific user."""
        try:
            user_info = pwd.getpwnam(username)
            authorized_keys_file = Path(user_info.pw_dir) / '.ssh' / 'authorized_keys'
            
            if not authorized_keys_file.exists():
                return None
            
            ssh_info = SSHAccessInfo(
                user=username,
                authorized_keys_file=str(authorized_keys_file),
                key_count=0,
                keys=[],
                ssh_config_issues=[]
            )
            
            # Read authorized keys file
            try:
                with open(authorized_keys_file, 'r') as f:
                    lines = f.readlines()
                    
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        ssh_info.key_count += 1
                        key_info = self._parse_ssh_key(line)
                        if key_info:
                            ssh_info.keys.append(key_info)
            except Exception as e:
                ssh_info.ssh_config_issues.append(f"Could not read authorized_keys: {str(e)}")
            
            # Check SSH configuration issues
            self._check_ssh_config_security(ssh_info)
            
            return ssh_info if ssh_info.key_count > 0 else None
            
        except Exception as e:
            self.log_debug(f"Could not get SSH info for {username}: {str(e)}")
            return None
    
    def _parse_ssh_key(self, key_line: str) -> Optional[Dict[str, Any]]:
        """Parse SSH public key line to extract information."""
        try:
            parts = key_line.split()
            if len(parts) >= 2:
                key_type = parts[0]
                key_data = parts[1]
                comment = parts[2] if len(parts) > 2 else ""
                
                # Check key strength
                key_length = len(key_data)
                key_strength = self._assess_key_strength(key_type, key_data)
                
                return {
                    'type': key_type,
                    'length': key_length,
                    'comment': comment,
                    'strength': key_strength,
                    'is_weak': key_strength in ['weak', 'very_weak']
                }
        except Exception:
            return None
    
    def _assess_key_strength(self, key_type: str, key_data: str) -> str:
        """Assess SSH key strength based on type and length."""
        try:
            if key_type.startswith('ssh-rsa'):
                # RSA key - check length
                import base64
                decoded = base64.b64decode(key_data)
                # RSA key blob structure: 4 bytes length + "ssh-rsa" + 4 bytes + exponent + 4 bytes + modulus
                # Approximate key length from base64 length
                if len(key_data) < 300:  # Approximately < 1024 bits
                    return 'very_weak'
                elif len(key_data) < 600:  # Approximately < 2048 bits
                    return 'weak'
                else:
                    return 'strong'
            elif key_type.startswith('ssh-ed25519'):
                return 'strong'  # Ed25519 is always strong
            elif key_type.startswith('ecdsa-sha2'):
                return 'strong'  # ECDSA with SHA2 is strong
            else:
                return 'unknown'
        except Exception:
            return 'unknown'
    
    def _check_ssh_config_security(self, ssh_info: SSHAccessInfo):
        """Check SSH configuration for security issues."""
        try:
            # Check for weak keys
            weak_keys = [key for key in ssh_info.keys if key.get('is_weak', False)]
            if weak_keys:
                self.security_issues.append(
                    self.create_issue(
                        title=f"Weak SSH keys for user {ssh_info.user}",
                        description=f"User {ssh_info.user} has {len(weak_keys)} weak SSH key(s)",
                        severity=SeverityLevel.HIGH,
                        recommendation="Replace weak SSH keys with stronger ones (RSA 2048+ bits, Ed25519, or ECDSA)",
                        affected_files=[ssh_info.authorized_keys_file],
                        evidence=[f"Weak keys: {[key['type'] for key in weak_keys]}"]
                    )
                )
            
            # Check authorized_keys file permissions
            try:
                permissions = FileUtils.get_file_permissions(ssh_info.authorized_keys_file)
                numeric_perms = permissions.get('numeric', '0000')
                if numeric_perms != '600':
                    self.security_issues.append(
                        self.create_issue(
                            title=f"Weak permissions on authorized_keys for user {ssh_info.user}",
                            description=f"authorized_keys file has weak permissions ({numeric_perms})",
                            severity=SeverityLevel.MEDIUM,
                            recommendation=f"Set secure permissions: chmod 600 {ssh_info.authorized_keys_file}",
                            affected_files=[ssh_info.authorized_keys_file],
                            evidence=[f"Current permissions: {numeric_perms}"]
                        )
                    )
            except Exception:
                pass
                
        except Exception as e:
            self.log_debug(f"Could not check SSH config security for {ssh_info.user}: {str(e)}")
    
    def _check_account_status(self):
        """Check account status for inactive and expired accounts."""
        self.log_debug("Checking account status")
        
        try:
            current_time = datetime.now()
            max_inactive_days = self.get_config_value('security.max_inactive_days', 90)
            max_password_age = self.get_config_value('security.max_password_age', 90)
            
            for user in self.users:
                # Skip system accounts (UID < 1000) for some checks
                if user.uid < 1000 and user.username not in self.root_users:
                    continue
                
                # Check for inactive accounts
                if user.last_login:
                    inactive_days = (current_time - user.last_login).days
                    if inactive_days > max_inactive_days:
                        self.inactive_users.append(user.username)
                        self.security_issues.append(
                            self.create_issue(
                                title=f"Inactive user account: {user.username}",
                                description=f"User {user.username} has not logged in for {inactive_days} days",
                                severity=SeverityLevel.MEDIUM,
                                recommendation="Review and disable or remove inactive accounts",
                                affected_files=[],
                                evidence=[f"Last login: {user.last_login}"]
                            )
                        )
                else:
                    # No login history - could be new or never used
                    self.security_issues.append(
                        self.create_issue(
                            title=f"No login history for user: {user.username}",
                            description=f"User {user.username} has no recorded login history",
                            severity=SeverityLevel.LOW,
                            recommendation="Verify if this is a legitimate account and monitor usage",
                            affected_files=[],
                            evidence=[f"User created: {user.password_last_changed}"]
                        )
                    )
                
                # Check for expired accounts
                if user.account_expires and user.account_expires < current_time:
                    self.security_issues.append(
                        self.create_issue(
                            title=f"Expired user account: {user.username}",
                            description=f"User {user.username} account expired on {user.account_expires}",
                            severity=SeverityLevel.HIGH,
                            recommendation="Disable expired accounts immediately",
                            affected_files=[],
                            evidence=[f"Account expiration: {user.account_expires}"]
                        )
                    )
                
                # Check for expired passwords
                if user.password_expires and user.password_expires < current_time:
                    self.security_issues.append(
                        self.create_issue(
                            title=f"Expired password for user: {user.username}",
                            description=f"User {user.username} password expired on {user.password_expires}",
                            severity=SeverityLevel.HIGH,
                            recommendation="Force password change for users with expired passwords",
                            affected_files=[],
                            evidence=[f"Password expiration: {user.password_expires}"]
                        )
                    )
                
                # Check password age
                if user.password_last_changed:
                    password_age = (current_time - user.password_last_changed).days
                    if password_age > max_password_age:
                        self.security_issues.append(
                            self.create_issue(
                                title=f"Password older than {max_password_age} days for user: {user.username}",
                                description=f"User {user.username} password is {password_age} days old",
                                severity=SeverityLevel.MEDIUM,
                                recommendation="Enforce regular password changes",
                                affected_files=[],
                                evidence=[f"Last password change: {user.password_last_changed}"]
                            )
                        )
                
                # Check for locked accounts that should be disabled
                if user.is_locked and user.uid >= 1000:  # Not root
                    self.security_issues.append(
                        self.create_issue(
                            title=f"Locked user account: {user.username}",
                            description=f"User {user.username} account is locked but still exists",
                            severity=SeverityLevel.LOW,
                            recommendation="Consider disabling or removing locked accounts after investigation",
                            affected_files=[],
                            evidence=[f"Account is locked: {user.is_locked}"]
                        )
                    )
            
            self.log_debug(f"Found {len(self.inactive_users)} inactive users")
            
        except Exception as e:
            self.log_error(f"Failed to check account status: {str(e)}")
            self.security_issues.append(
                self.create_issue(
                    title="Account Status Check Failed",
                    description=f"Unable to check account status: {str(e)}",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Check system permissions and user database access",
                    affected_files=[],
                    evidence=[f"Error: {str(e)}"]
                )
            )
    
    def _check_security_issues(self):
        """Check for additional security issues."""
        self.log_debug("Checking for additional security issues")
        
        try:
            # Check for duplicate UIDs
            uid_counts = {}
            for user in self.users:
                uid_counts[user.uid] = uid_counts.get(user.uid, 0) + 1
            
            duplicate_uids = {uid: count for uid, count in uid_counts.items() if count > 1}
            if duplicate_uids:
                users_with_dup_uids = [u.username for u in self.users if u.uid in duplicate_uids]
                self.security_issues.append(
                    self.create_issue(
                        title="Duplicate UIDs detected",
                        description=f"Users with duplicate UIDs: {', '.join(users_with_dup_uids)}",
                        severity=SeverityLevel.HIGH,
                        recommendation="Assign unique UIDs to all users",
                        affected_files=['/etc/passwd'],
                        evidence=[f"Duplicate UIDs: {duplicate_uids}"]
                    )
                )
            
            # Check for duplicate GIDs
            gid_counts = {}
            for group_name, members in self.groups.items():
                try:
                    gid = grp.getgrnam(group_name).gr_gid
                    gid_counts[gid] = gid_counts.get(gid, 0) + 1
                except Exception:
                    pass
            
            duplicate_gids = {gid: count for gid, count in gid_counts.items() if count > 1}
            if duplicate_gids:
                groups_with_dup_gids = [name for name, members in self.groups.items() 
                                      if grp.getgrnam(name).gr_gid in duplicate_gids]
                self.security_issues.append(
                    self.create_issue(
                        title="Duplicate GIDs detected",
                        description=f"Groups with duplicate GIDs: {', '.join(groups_with_dup_gids)}",
                        severity=SeverityLevel.MEDIUM,
                        recommendation="Assign unique GIDs to all groups",
                        affected_files=['/etc/group'],
                        evidence=[f"Duplicate GIDs: {duplicate_gids}"]
                    )
                )
            
            # Check for users with no password (empty password field)
            for user in self.users:
                if os.access('/etc/shadow', os.R_OK):
                    try:
                        with open('/etc/shadow', 'r') as f:
                            for line in f:
                                parts = line.strip().split(':')
                                if len(parts) >= 2 and parts[0] == user.username:
                                    if parts[1] == '':  # Empty password
                                        self.security_issues.append(
                                            self.create_issue(
                                                title=f"User with empty password: {user.username}",
                                                description=f"User {user.username} has no password set",
                                                severity=SeverityLevel.CRITICAL,
                                                recommendation="Set strong passwords for all user accounts",
                                                affected_files=['/etc/shadow'],
                                                evidence=[f"User: {user.username}"]
                                            )
                                        )
                                    break
                    except Exception:
                        pass
            
            # Check for default accounts that should be removed
            default_accounts = ['ftp', 'games', 'gopher', 'lp', 'news', 'uucp', 'operator']
            existing_default_accounts = [acc for acc in default_accounts if acc in [u.username for u in self.users]]
            if existing_default_accounts:
                self.security_issues.append(
                    self.create_issue(
                        title="Default system accounts present",
                        description=f"Default accounts found: {', '.join(existing_default_accounts)}",
                        severity=SeverityLevel.LOW,
                        recommendation="Review and remove unnecessary default accounts",
                        affected_files=['/etc/passwd'],
                        evidence=[f"Default accounts: {existing_default_accounts}"]
                    )
                )
            
            # Check for multiple root users (UID 0)
            if len(self.root_users) > 1:
                self.security_issues.append(
                    self.create_issue(
                        title="Multiple users with root privileges (UID 0)",
                        description=f"Multiple users have UID 0: {', '.join(self.root_users)}",
                        severity=SeverityLevel.CRITICAL,
                        recommendation="Limit root access to minimum necessary accounts",
                        affected_files=['/etc/passwd'],
                        evidence=[f"Root users: {', '.join(self.root_users)}"]
                    )
                )
            
        except Exception as e:
            self.log_error(f"Failed to check security issues: {str(e)}")
    
    def _get_user_summary(self) -> Dict[str, Any]:
        """Get summary of user information."""
        return {
            'total_users': len(self.users),
            'system_users': len([u for u in self.users if u.uid < 1000]),
            'regular_users': len([u for u in self.users if u.uid >= 1000]),
            'root_users': list(self.root_users),
            'sudo_users': list(self.sudo_users),
            'users_with_ssh': list(self.ssh_access.keys()),
            'inactive_users': self.inactive_users
        }
    
    def _get_group_summary(self) -> Dict[str, Any]:
        """Get summary of group information."""
        return {
            'total_groups': len(self.groups),
            'groups_with_members': {name: len(members) for name, members in self.groups.items() if members},
            'admin_groups': [name for name in ['sudo', 'wheel', 'admin'] if name in self.groups]
        }


def create_module(config):
    """
    Factory function to create a UserAuditModule instance.
    
    Args:
        config: Configuration object
        
    Returns:
        UserAuditModule instance
    """
    return UserAuditModule(config)