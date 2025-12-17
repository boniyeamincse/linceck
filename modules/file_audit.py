"""
File & Directory Permissions Audit Module for Linux Server Auditor

This module audits file system permissions, access controls, and security configurations
 including critical file permissions, world-writable files, home directory security,
 setuid/setgid analysis, and sensitive file detection.

Compliance: SC-28 (Protection of Information at Rest), CM-6 (Configuration Settings)
"""

import os
import re
import json
import yaml
import subprocess
import logging
import time
import stat
import pwd
import grp
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set, Union
from pathlib import Path
from dataclasses import dataclass, asdict

from core.base_module import BaseModule, SecurityIssue, ModuleResult, ModuleStatus, SeverityLevel
from core.logger import get_logger
from utils.helpers import SystemUtils, FileUtils, CommandUtils, SecurityUtils, TimeUtils


@dataclass
class FilePermissionInfo:
    """File permission information structure."""
    path: str
    permissions: str
    numeric_perms: str
    owner: str
    group: str
    size: int
    modified: str
    is_suid: bool = False
    is_sgid: bool = False
    is_sticky: bool = False
    is_world_writable: bool = False


@dataclass
class DirectoryAnalysis:
    """Directory analysis results."""
    path: str
    total_files: int
    world_writable_files: int
    suid_files: int
    sgid_files: int
    issues: List[str]


class FileAuditModule(BaseModule):
    """
    File & Directory Permissions Audit Module
    
    Audits file system permissions, access controls, and security configurations.
    """
    
    def __init__(self, config):
        """
        Initialize the File Audit Module.
        
        Args:
            config: Configuration object
        """
        super().__init__(config)
        self.critical_files = []  # List of FilePermissionInfo objects
        self.world_writable_files = []  # World-writable files
        self.home_directories = {}  # Home directory analysis
        self.suid_files = []  # SUID files
        self.sgid_files = []  # SGID files
        self.sensitive_files = []  # Sensitive files in unexpected locations
        self.security_issues = []
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        
    @property
    def module_name(self) -> str:
        """Return the module name."""
        return "File & Directory Permissions"
    
    @property
    def description(self) -> str:
        """Return a brief description of what this module audits."""
        return "Audits file system permissions, access controls, critical file security, and detects misconfigurations"
    
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
        return False  # Most checks can run without root
    
    def check_dependencies(self) -> bool:
        """
        Check if required dependencies and permissions are available.
        
        Returns:
            True if dependencies are met, False otherwise
        """
        try:
            # Check if we can access critical system files
            critical_paths = ['/etc', '/home', '/tmp', '/var']
            for path in critical_paths:
                if not os.path.exists(path):
                    self.log_error(f"Cannot access critical path: {path}")
                    return False
            
            # Check for required commands
            required_commands = ['find', 'stat', 'ls']
            for cmd in required_commands:
                if not CommandUtils.check_command_exists(cmd):
                    self.log_warning(f"Command '{cmd}' not found - some checks may be limited")
            
            self.log_debug("File audit dependencies check passed")
            return True
            
        except Exception as e:
            self.log_error(f"Dependency check failed: {str(e)}")
            return False
    
    def run(self) -> ModuleResult:
        """
        Execute the file and directory permissions audit.
        
        Returns:
            ModuleResult containing the audit results
        """
        self.log_info("Starting file and directory permissions audit")
        
        try:
            # Gather file and directory information
            self._audit_critical_files()
            self._audit_world_writable_files()
            self._audit_home_directories()
            self._audit_suid_sgid_files()
            self._audit_sensitive_files()
            self._check_file_system_security()
            
            # Calculate score
            score = self.calculate_score_from_issues(self.security_issues, 100.0)
            
            # Prepare metadata
            metadata = {
                'total_critical_files': len(self.critical_files),
                'world_writable_files_count': len(self.world_writable_files),
                'suid_files_count': len(self.suid_files),
                'sgid_files_count': len(self.sgid_files),
                'sensitive_files_count': len(self.sensitive_files),
                'home_directories_analyzed': len(self.home_directories),
                'audit_timestamp': self.format_timestamp(),
                'critical_file_summary': self._get_critical_file_summary(),
                'security_summary': self._get_security_summary()
            }
            
            self.log_info(f"File and directory permissions audit completed with score: {score}")
            
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                score=score,
                issues=self.security_issues,
                metadata=metadata,
                timestamp=self.format_timestamp()
            )
            
        except Exception as e:
            self.log_error(f"File and directory permissions audit failed: {str(e)}")
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
    
    def _audit_critical_files(self):
        """Audit critical system files for proper permissions."""
        self.log_debug("Auditing critical system files")
        
        # Define critical files and their expected permissions
        critical_file_rules = {
            '/etc/passwd': {'owner': 'root', 'group': 'root', 'perms': '644'},
            '/etc/shadow': {'owner': 'root', 'group': 'shadow', 'perms': '640'},
            '/etc/group': {'owner': 'root', 'group': 'root', 'perms': '644'},
            '/etc/gshadow': {'owner': 'root', 'group': 'shadow', 'perms': '640'},
            '/etc/sudoers': {'owner': 'root', 'group': 'root', 'perms': '440'},
            '/etc/ssh/sshd_config': {'owner': 'root', 'group': 'root', 'perms': '644'},
            '/etc/hosts': {'owner': 'root', 'group': 'root', 'perms': '644'},
            '/etc/hosts.allow': {'owner': 'root', 'group': 'root', 'perms': '644'},
            '/etc/hosts.deny': {'owner': 'root', 'group': 'root', 'perms': '644'},
            '/etc/crontab': {'owner': 'root', 'group': 'root', 'perms': '644'},
            '/etc/fstab': {'owner': 'root', 'group': 'root', 'perms': '644'},
            '/boot/grub/grub.cfg': {'owner': 'root', 'group': 'root', 'perms': '600'},
            '/etc/crontab': {'owner': 'root', 'group': 'root', 'perms': '644'},
            '/etc/cron.hourly': {'owner': 'root', 'group': 'root', 'perms': '755'},
            '/etc/cron.daily': {'owner': 'root', 'group': 'root', 'perms': '755'},
            '/etc/cron.weekly': {'owner': 'root', 'group': 'root', 'perms': '755'},
            '/etc/cron.monthly': {'owner': 'root', 'group': 'root', 'perms': '755'},
            '/etc/cron.d': {'owner': 'root', 'group': 'root', 'perms': '755'},
        }
        
        for file_path, expected in critical_file_rules.items():
            if not os.path.exists(file_path):
                continue
            
            try:
                # Get file permissions
                file_info = self._get_file_permission_info(file_path)
                if file_info:
                    self.critical_files.append(file_info)
                    
                    # Check permissions
                    self._check_critical_file_permissions(file_path, file_info, expected)
                    
                    # Check ownership
                    self._check_critical_file_ownership(file_path, file_info, expected)
                    
            except Exception as e:
                self.log_debug(f"Could not audit critical file {file_path}: {str(e)}")
                self.security_issues.append(
                    self.create_issue(
                        title=f"Critical file audit failed: {file_path}",
                        description=f"Unable to audit critical file {file_path}: {str(e)}",
                        severity=SeverityLevel.MEDIUM,
                        recommendation="Ensure the file exists and is accessible for auditing",
                        affected_files=[file_path],
                        evidence=[f"Error: {str(e)}"]
                    )
                )
    
    def _get_file_permission_info(self, file_path: str) -> Optional[FilePermissionInfo]:
        """Get detailed file permission information."""
        try:
            stat_info = os.stat(file_path)
            file_stat = stat.filemode(stat_info.st_mode)
            numeric_perms = oct(stat_info.st_mode)[-4:]
            
            # Get owner and group
            try:
                owner = pwd.getpwuid(stat_info.st_uid).pw_name
            except:
                owner = str(stat_info.st_uid)
            
            try:
                group = grp.getgrgid(stat_info.st_gid).gr_name
            except:
                group = str(stat_info.st_gid)
            
            # Check special bits
            is_suid = bool(stat_info.st_mode & stat.S_ISUID)
            is_sgid = bool(stat_info.st_mode & stat.S_ISGID)
            is_sticky = bool(stat_info.st_mode & stat.S_ISVTX)
            is_world_writable = bool(stat_info.st_mode & stat.S_IWOTH)
            
            return FilePermissionInfo(
                path=file_path,
                permissions=file_stat,
                numeric_perms=numeric_perms,
                owner=owner,
                group=group,
                size=stat_info.st_size,
                modified=datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                is_suid=is_suid,
                is_sgid=is_sgid,
                is_sticky=is_sticky,
                is_world_writable=is_world_writable
            )
            
        except Exception as e:
            self.log_debug(f"Could not get permissions for {file_path}: {str(e)}")
            return None
    
    def _check_critical_file_permissions(self, file_path: str, file_info: FilePermissionInfo, expected: Dict[str, str]):
        """Check if critical file has correct permissions."""
        expected_perms = expected.get('perms', '644')
        actual_perms = file_info.numeric_perms
        
        if actual_perms != expected_perms:
            severity = SeverityLevel.HIGH if file_path in ['/etc/shadow', '/etc/gshadow', '/etc/sudoers'] else SeverityLevel.MEDIUM
            
            self.security_issues.append(
                self.create_issue(
                    title=f"Incorrect permissions on critical file: {file_path}",
                    description=f"File {file_path} has permissions {actual_perms}, expected {expected_perms}",
                    severity=severity,
                    recommendation=f"Set correct permissions: chmod {expected_perms} {file_path}",
                    affected_files=[file_path],
                    evidence=[f"Current permissions: {actual_perms}, Expected: {expected_perms}"]
                )
            )
    
    def _check_critical_file_ownership(self, file_path: str, file_info: FilePermissionInfo, expected: Dict[str, str]):
        """Check if critical file has correct ownership."""
        expected_owner = expected.get('owner', 'root')
        expected_group = expected.get('group', 'root')
        
        if file_info.owner != expected_owner or file_info.group != expected_group:
            severity = SeverityLevel.HIGH if file_path in ['/etc/shadow', '/etc/gshadow', '/etc/sudoers'] else SeverityLevel.MEDIUM
            
            self.security_issues.append(
                self.create_issue(
                    title=f"Incorrect ownership on critical file: {file_path}",
                    description=f"File {file_path} owned by {file_info.owner}:{file_info.group}, expected {expected_owner}:{expected_group}",
                    severity=severity,
                    recommendation=f"Set correct ownership: chown {expected_owner}:{expected_group} {file_path}",
                    affected_files=[file_path],
                    evidence=[f"Current owner: {file_info.owner}:{file_info.group}, Expected: {expected_owner}:{expected_group}"]
                )
            )
    
    def _audit_world_writable_files(self):
        """Audit world-writable files and directories."""
        self.log_debug("Auditing world-writable files")
        
        try:
            # Common directories to check for world-writable files
            search_paths = ['/tmp', '/var/tmp', '/home', '/etc', '/usr', '/opt']
            
            for search_path in search_paths:
                if not os.path.exists(search_path):
                    continue
                
                try:
                    # Use find command to locate world-writable files
                    result = CommandUtils.run_command(
                        ['find', search_path, '-type', 'f', '-perm', '-002', '-ls'],
                        timeout=60
                    )
                    
                    if result['success'] and result['stdout']:
                        lines = result['stdout'].strip().split('\n')
                        for line in lines:
                            if line.strip():
                                # Parse find output to extract file path
                                parts = line.split()
                                if len(parts) >= 11:
                                    file_path = ' '.join(parts[10:])  # Path is after the file details
                                    if os.path.exists(file_path):
                                        file_info = self._get_file_permission_info(file_path)
                                        if file_info and file_info.is_world_writable:
                                            self.world_writable_files.append(file_info)
                                            
                                            # Check if this is a sensitive file
                                            if self._is_sensitive_file(file_path):
                                                self.security_issues.append(
                                                    self.create_issue(
                                                        title=f"World-writable sensitive file: {file_path}",
                                                        description=f"Sensitive file {file_path} is world-writable",
                                                        severity=SeverityLevel.CRITICAL,
                                                        recommendation="Remove world-writable permission: chmod o-w " + file_path,
                                                        affected_files=[file_path],
                                                        evidence=[f"Permissions: {file_info.permissions}"]
                                                    )
                                                )
                                            else:
                                                self.security_issues.append(
                                                    self.create_issue(
                                                        title=f"World-writable file: {file_path}",
                                                        description=f"File {file_path} is world-writable",
                                                        severity=SeverityLevel.MEDIUM,
                                                        recommendation="Review if world-writable permission is necessary",
                                                        affected_files=[file_path],
                                                        evidence=[f"Permissions: {file_info.permissions}"]
                                                    )
                                                )
                
                except Exception as e:
                    self.log_debug(f"Could not audit world-writable files in {search_path}: {str(e)}")
                    
        except Exception as e:
            self.log_error(f"Failed to audit world-writable files: {str(e)}")
            self.security_issues.append(
                self.create_issue(
                    title="World-writable file audit failed",
                    description=f"Unable to audit world-writable files: {str(e)}",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Manual review of world-writable files required",
                    affected_files=[],
                    evidence=[f"Error: {str(e)}"]
                )
            )
    
    def _audit_home_directories(self):
        """Audit home directory permissions."""
        self.log_debug("Auditing home directories")
        
        try:
            # Get all users and their home directories
            for user_info in pwd.getpwall():
                home_dir = user_info.pw_dir
                username = user_info.pw_name
                
                # Skip system users (UID < 1000) and non-standard home directories
                if user_info.pw_uid < 1000 or not home_dir or not os.path.exists(home_dir):
                    continue
                
                try:
                    # Check home directory permissions
                    dir_info = self._get_file_permission_info(home_dir)
                    if dir_info:
                        self.home_directories[username] = dir_info
                        
                        # Home directories should be 755 or 700
                        if dir_info.numeric_perms not in ['755', '700']:
                            self.security_issues.append(
                                self.create_issue(
                                    title=f"Insecure home directory permissions: {home_dir}",
                                    description=f"Home directory {home_dir} has permissions {dir_info.numeric_perms}, should be 755 or 700",
                                    severity=SeverityLevel.MEDIUM,
                                    recommendation=f"Set secure permissions: chmod 755 {home_dir} (or 700 for private access)",
                                    affected_files=[home_dir],
                                    evidence=[f"Current permissions: {dir_info.permissions}"]
                                )
                            )
                        
                        # Check for world-writable files in home directory
                        self._check_home_directory_contents(home_dir, username)
                
                except Exception as e:
                    self.log_debug(f"Could not audit home directory {home_dir}: {str(e)}")
                    
        except Exception as e:
            self.log_error(f"Failed to audit home directories: {str(e)}")
            self.security_issues.append(
                self.create_issue(
                    title="Home directory audit failed",
                    description=f"Unable to audit home directories: {str(e)}",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Manual review of home directory permissions required",
                    affected_files=[],
                    evidence=[f"Error: {str(e)}"]
                )
            )
    
    def _check_home_directory_contents(self, home_dir: str, username: str):
        """Check for security issues in home directory contents."""
        try:
            # Check for world-writable files
            result = CommandUtils.run_command(
                ['find', home_dir, '-type', 'f', '-perm', '-002'],
                timeout=30
            )
            
            if result['success'] and result['stdout']:
                world_writable_files = result['stdout'].strip().split('\n')
                for file_path in world_writable_files:
                    if file_path.strip():
                        self.security_issues.append(
                            self.create_issue(
                                title=f"World-writable file in home directory: {file_path}",
                                description=f"File {file_path} in {username}'s home directory is world-writable",
                                severity=SeverityLevel.MEDIUM,
                                recommendation="Remove world-writable permission: chmod o-w " + file_path,
                                affected_files=[file_path],
                                evidence=[f"User: {username}"]
                            )
                        )
            
            # Check for .rhosts and .shosts files
            dangerous_files = ['.rhosts', '.shosts', 'hosts.equiv']
            for dangerous_file in dangerous_files:
                file_path = os.path.join(home_dir, dangerous_file)
                if os.path.exists(file_path):
                    self.security_issues.append(
                        self.create_issue(
                            title=f"Dangerous file in home directory: {file_path}",
                            description=f"Dangerous file {file_path} found in {username}'s home directory",
                            severity=SeverityLevel.HIGH,
                            recommendation="Remove the file: rm " + file_path,
                            affected_files=[file_path],
                            evidence=[f"File: {dangerous_file}, User: {username}"]
                        )
                    )
            
            # Check SSH directory permissions
            ssh_dir = os.path.join(home_dir, '.ssh')
            if os.path.exists(ssh_dir):
                ssh_info = self._get_file_permission_info(ssh_dir)
                if ssh_info and ssh_info.numeric_perms != '700':
                    self.security_issues.append(
                        self.create_issue(
                            title=f"Insecure SSH directory permissions: {ssh_dir}",
                            description=f"SSH directory {ssh_dir} has permissions {ssh_info.numeric_perms}, should be 700",
                            severity=SeverityLevel.HIGH,
                            recommendation="Set secure permissions: chmod 700 " + ssh_dir,
                            affected_files=[ssh_dir],
                            evidence=[f"Current permissions: {ssh_info.permissions}"]
                        )
                    )
                
                # Check SSH key file permissions
                ssh_files = ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'authorized_keys']
                for ssh_file in ssh_files:
                    key_file = os.path.join(ssh_dir, ssh_file)
                    if os.path.exists(key_file):
                        key_info = self._get_file_permission_info(key_file)
                        if key_info and key_info.numeric_perms not in ['600', '644']:
                            severity = SeverityLevel.HIGH if ssh_file != 'authorized_keys' else SeverityLevel.MEDIUM
                            self.security_issues.append(
                                self.create_issue(
                                    title=f"Insecure SSH key permissions: {key_file}",
                                    description=f"SSH key file {key_file} has permissions {key_info.numeric_perms}",
                                    severity=severity,
                                    recommendation="Set secure permissions: chmod 600 " + key_file,
                                    affected_files=[key_file],
                                    evidence=[f"Current permissions: {key_info.permissions}"]
                                )
                            )
        
        except Exception as e:
            self.log_debug(f"Could not check home directory contents for {home_dir}: {str(e)}")
    
    def _audit_suid_sgid_files(self):
        """Audit SUID and SGID files."""
        self.log_debug("Auditing SUID and SGID files")
        
        try:
            # Common safe SUID/SGID files that are typically acceptable
            safe_suid_files = {
                '/usr/bin/passwd', '/usr/bin/sudo', '/usr/bin/gpasswd', '/usr/bin/mount',
                '/usr/bin/umount', '/usr/bin/su', '/usr/bin/newgrp', '/usr/bin/chfn', '/usr/bin/chsh',
                '/bin/ping', '/bin/ping6', '/usr/bin/traceroute', '/usr/bin/traceroute6'
            }
            
            # Search for SUID files
            result = CommandUtils.run_command(
                ['find', '/', '-type', 'f', '-perm', '-4000', '-ls'],
                timeout=120
            )
            
            if result['success'] and result['stdout']:
                lines = result['stdout'].strip().split('\n')
                for line in lines:
                    if line.strip():
                        # Parse find output
                        parts = line.split()
                        if len(parts) >= 11:
                            file_path = ' '.join(parts[10:])
                            if os.path.exists(file_path):
                                file_info = self._get_file_permission_info(file_path)
                                if file_info and file_info.is_suid:
                                    self.suid_files.append(file_info)
                                    
                                    # Check if this is an unexpected SUID file
                                    if file_path not in safe_suid_files:
                                        self.security_issues.append(
                                            self.create_issue(
                                                title=f"Unexpected SUID file: {file_path}",
                                                description=f"SUID file {file_path} found - verify if this is intentional",
                                                severity=SeverityLevel.HIGH,
                                                recommendation="Review if SUID bit is necessary for this file",
                                                affected_files=[file_path],
                                                evidence=[f"Permissions: {file_info.permissions}"]
                                            )
                                        )
            
            # Search for SGID files
            result = CommandUtils.run_command(
                ['find', '/', '-type', 'f', '-perm', '-2000', '-ls'],
                timeout=120
            )
            
            if result['success'] and result['stdout']:
                lines = result['stdout'].strip().split('\n')
                for line in lines:
                    if line.strip():
                        # Parse find output
                        parts = line.split()
                        if len(parts) >= 11:
                            file_path = ' '.join(parts[10:])
                            if os.path.exists(file_path):
                                file_info = self._get_file_permission_info(file_path)
                                if file_info and file_info.is_sgid:
                                    self.sgid_files.append(file_info)
                                    
                                    # Check if this is an unexpected SGID file
                                    if file_path not in safe_suid_files:  # Using same safe list for simplicity
                                        self.security_issues.append(
                                            self.create_issue(
                                                title=f"Unexpected SGID file: {file_path}",
                                                description=f"SGID file {file_path} found - verify if this is intentional",
                                                severity=SeverityLevel.MEDIUM,
                                                recommendation="Review if SGID bit is necessary for this file",
                                                affected_files=[file_path],
                                                evidence=[f"Permissions: {file_info.permissions}"]
                                            )
                                        )
        
        except Exception as e:
            self.log_error(f"Failed to audit SUID/SGID files: {str(e)}")
            self.security_issues.append(
                self.create_issue(
                    title="SUID/SGID file audit failed",
                    description=f"Unable to audit SUID/SGID files: {str(e)}",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Manual review of SUID/SGID files required",
                    affected_files=[],
                    evidence=[f"Error: {str(e)}"]
                )
            )
    
    def _audit_sensitive_files(self):
        """Audit for sensitive files in unexpected locations."""
        self.log_debug("Auditing for sensitive files in unexpected locations")
        
        try:
            # Define sensitive file patterns and their expected locations
            sensitive_patterns = {
                r'\.key$': ['/etc/ssl/', '/etc/pki/', '/root/'],
                r'\.pem$': ['/etc/ssl/', '/etc/pki/', '/root/'],
                r'\.crt$': ['/etc/ssl/', '/etc/pki/', '/root/'],
                r'\.p12$': ['/etc/ssl/', '/etc/pki/', '/root/'],
                r'passwords?\.(txt|csv)$': ['/etc/', '/root/'],
                r'secrets?\.(txt|csv)$': ['/etc/', '/root/'],
                r'credentials?\.(txt|csv)$': ['/etc/', '/root/'],
                r'config\.(php|py|js|json)$': ['/etc/', '/opt/', '/usr/local/'],
                r'\.env$': ['/etc/', '/opt/', '/usr/local/'],
                r'db\.(conf|config)$': ['/etc/', '/opt/', '/usr/local/'],
            }
            
            # Search for sensitive files
            search_paths = ['/tmp', '/var/tmp', '/home', '/var/log', '/opt', '/usr/local']
            
            for search_path in search_paths:
                if not os.path.exists(search_path):
                    continue
                
                try:
                    # Find all files in the directory
                    result = CommandUtils.run_command(
                        ['find', search_path, '-type', 'f', '-name', '*'],
                        timeout=60
                    )
                    
                    if result['success'] and result['stdout']:
                        files = result['stdout'].strip().split('\n')
                        for file_path in files:
                            file_path = file_path.strip()
                            if not file_path or not os.path.exists(file_path):
                                continue
                            
                            # Check against sensitive patterns
                            for pattern, allowed_locations in sensitive_patterns.items():
                                if re.search(pattern, file_path, re.IGNORECASE):
                                    # Check if file is in allowed location
                                    is_allowed = any(file_path.startswith(loc) for loc in allowed_locations)
                                    
                                    if not is_allowed:
                                        file_info = self._get_file_permission_info(file_path)
                                        severity = SeverityLevel.HIGH if self._is_sensitive_file(file_path) else SeverityLevel.MEDIUM
                                        
                                        self.sensitive_files.append(file_path)
                                        self.security_issues.append(
                                            self.create_issue(
                                                title=f"Sensitive file in unexpected location: {file_path}",
                                                description=f"Sensitive file {file_path} found outside expected location",
                                                severity=severity,
                                                recommendation="Move file to secure location or restrict access",
                                                affected_files=[file_path],
                                                evidence=[f"File pattern: {pattern}"]
                                            )
                                        )
                
                except Exception as e:
                    self.log_debug(f"Could not audit sensitive files in {search_path}: {str(e)}")
        
        except Exception as e:
            self.log_error(f"Failed to audit sensitive files: {str(e)}")
            self.security_issues.append(
                self.create_issue(
                    title="Sensitive file audit failed",
                    description=f"Unable to audit sensitive files: {str(e)}",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Manual review for sensitive files required",
                    affected_files=[],
                    evidence=[f"Error: {str(e)}"]
                )
            )
    
    def _check_file_system_security(self):
        """Check file system security settings."""
        self.log_debug("Checking file system security")
        
        try:
            # Check mount options for critical partitions
            self._check_mount_options()
            
            # Check for unencrypted file systems
            self._check_encryption_status()
            
            # Check for NFS exports with insecure options
            self._check_nfs_exports()
            
        except Exception as e:
            self.log_error(f"Failed to check file system security: {str(e)}")
            self.security_issues.append(
                self.create_issue(
                    title="File system security check failed",
                    description=f"Unable to check file system security: {str(e)}",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Manual review of file system security required",
                    affected_files=[],
                    evidence=[f"Error: {str(e)}"]
                )
            )
    
    def _check_mount_options(self):
        """Check mount options for security."""
        try:
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        device, mount_point, fs_type, options = parts[:4]
                        
                        # Skip non-disk file systems
                        if fs_type in ['proc', 'sysfs', 'devtmpfs', 'tmpfs']:
                            continue
                        
                        # Check for security-sensitive mount points
                        if mount_point in ['/', '/tmp', '/var', '/home']:
                            # Check for nosuid option
                            if 'nosuid' not in options and mount_point != '/':
                                self.security_issues.append(
                                    self.create_issue(
                                        title=f"Missing nosuid on {mount_point}",
                                        description=f"File system {mount_point} mounted without nosuid option",
                                        severity=SeverityLevel.MEDIUM,
                                        recommendation=f"Add nosuid option to {mount_point} mount",
                                        affected_files=[mount_point],
                                        evidence=[f"Current options: {options}"]
                                    )
                                )
                            
                            # Check for nodev option on /tmp and /var
                            if mount_point in ['/tmp', '/var'] and 'nodev' not in options:
                                self.security_issues.append(
                                    self.create_issue(
                                        title=f"Missing nodev on {mount_point}",
                                        description=f"File system {mount_point} mounted without nodev option",
                                        severity=SeverityLevel.MEDIUM,
                                        recommendation=f"Add nodev option to {mount_point} mount",
                                        affected_files=[mount_point],
                                        evidence=[f"Current options: {options}"]
                                    )
                                )
        
        except Exception as e:
            self.log_debug(f"Could not check mount options: {str(e)}")
    
    def _check_encryption_status(self):
        """Check if sensitive file systems are encrypted."""
        try:
            # Check if /home is encrypted (simplified check)
            result = CommandUtils.run_command(['lsblk', '-o', 'NAME,TYPE,MOUNTPOINT,ENCRYPTION'], timeout=10)
            
            if result['success'] and result['stdout']:
                # This is a simplified check - in practice, you'd want more comprehensive encryption detection
                if '/home' in result['stdout'] and 'luks' not in result['stdout'].lower():
                    self.security_issues.append(
                        self.create_issue(
                            title="Home directory encryption not detected",
                            description="Home directory partition may not be encrypted",
                            severity=SeverityLevel.LOW,
                            recommendation="Consider encrypting home directory partition",
                            affected_files=['/home'],
                            evidence=["Manual verification required"]
                        )
                    )
        
        except Exception as e:
            self.log_debug(f"Could not check encryption status: {str(e)}")
    
    def _check_nfs_exports(self):
        """Check NFS exports for insecure options."""
        try:
            if os.path.exists('/etc/exports'):
                with open('/etc/exports', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Check for insecure options
                            if 'insecure' in line or 'rw' in line and 'root_squash' not in line:
                                self.security_issues.append(
                                    self.create_issue(
                                        title="Insecure NFS export configuration",
                                        description="NFS exports contain insecure options",
                                        severity=SeverityLevel.HIGH,
                                        recommendation="Review and secure NFS export options",
                                        affected_files=['/etc/exports'],
                                        evidence=[f"Export line: {line}"]
                                    )
                                )
        except Exception as e:
            self.log_debug(f"Could not check NFS exports: {str(e)}")
    
    def _is_sensitive_file(self, file_path: str) -> bool:
        """Check if a file is likely to be sensitive."""
        sensitive_patterns = [
            r'/etc/shadow', r'/etc/gshadow', r'/etc/sudoers',
            r'\.key$', r'\.pem$', r'\.crt$', r'\.p12$',
            r'passwords?\.', r'secrets?\.', r'credentials?\.',
            r'/root/.*', r'/etc/ssl/.*'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        return False
    
    def _get_critical_file_summary(self) -> Dict[str, Any]:
        """Get summary of critical file audit results."""
        return {
            'total_audited': len(self.critical_files),
            'issues_found': len([issue for issue in self.security_issues if any(cf.path in issue.affected_files for cf in self.critical_files)]),
            'files_with_issues': [cf.path for cf in self.critical_files if any(cf.path in issue.affected_files for issue in self.security_issues)]
        }
    
    def _get_security_summary(self) -> Dict[str, Any]:
        """Get overall security summary."""
        return {
            'world_writable_files': len(self.world_writable_files),
            'suid_files': len(self.suid_files),
            'sgid_files': len(self.sgid_files),
            'sensitive_files': len(self.sensitive_files),
            'home_directories': len(self.home_directories),
            'total_issues': len(self.security_issues)
        }


def create_module(config):
    """
    Factory function to create a FileAuditModule instance.
    
    Args:
        config: Configuration object
        
    Returns:
        FileAuditModule instance
    """
    return FileAuditModule(config)