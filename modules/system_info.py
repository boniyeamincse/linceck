"""
System Information Audit Module

This module audits system-level configurations and security settings including:
- OS information (type, version, kernel, hostname, uptime)
- Hardware details (CPU, RAM, disk usage, architecture)
- Kernel modules detection
- System configuration files
- Security checks and validations

Compliance: NIST CM-6 (Configuration Settings), SI-2 (Flaw Remediation)
"""

import os
import re
import sys
import json
import yaml
import subprocess
import platform
import socket
import psutil
import pwd
import grp
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

# Handle Windows compatibility for Unix-specific modules
try:
    import pwd
    import grp
    HAS_UNIX_MODULES = True
except ImportError:
    HAS_UNIX_MODULES = False

from core.base_module import BaseModule, SecurityIssue, ModuleResult, ModuleStatus, SeverityLevel
from core.logger import get_logger
from utils.helpers import SystemUtils, FileUtils, CommandUtils, NetworkUtils, SecurityUtils


class SystemInfoModule(BaseModule):
    """
    System Information Audit Module
    
    Audits system-level configurations and security settings.
    """
    
    def __init__(self, config):
        """
        Initialize the System Information Module.
        
        Args:
            config: Configuration object
        """
        super().__init__(config)
        self.os_info = {}
        self.hardware_info = {}
        self.kernel_modules = []
        self.system_config = {}
        self.security_issues = []
        
    @property
    def module_name(self) -> str:
        """Return the module name."""
        return "System Information"
    
    @property
    def description(self) -> str:
        """Return a brief description of what this module audits."""
        return "Audits system-level configurations, OS information, hardware details, kernel modules, and system security settings"
    
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
        return False
    
    def check_dependencies(self) -> bool:
        """
        Check if required dependencies and permissions are available.
        
        Returns:
            True if dependencies are met, False otherwise
        """
        try:
            # Check if psutil is available
            import psutil
            self.log_debug("psutil dependency check passed")
            
            # Check if we can access basic system information
            platform.system()
            socket.gethostname()
            self.log_debug("Basic system access check passed")
            
            return True
            
        except ImportError as e:
            self.log_error(f"Missing dependency: {str(e)}")
            return False
        except Exception as e:
            self.log_error(f"Dependency check failed: {str(e)}")
            return False
    
    def run(self) -> ModuleResult:
        """
        Execute the system information audit.
        
        Returns:
            ModuleResult containing the audit results
        """
        self.log_info("Starting system information audit")
        
        try:
            # Gather system information
            self._gather_os_info()
            self._gather_hardware_info()
            self._detect_kernel_modules()
            self._check_system_config()
            
            # Perform security checks
            self._check_kernel_security()
            self._check_system_updates()
            self._check_service_configuration()
            self._check_resource_usage()
            
            # Calculate score
            score = self.calculate_score_from_issues(self.security_issues, 100.0)
            
            # Prepare metadata
            metadata = {
                'os_info': self.os_info,
                'hardware_info': self.hardware_info,
                'kernel_modules_count': len(self.kernel_modules),
                'system_config_checks': len(self.system_config),
                'audit_timestamp': self.format_timestamp()
            }
            
            self.log_info(f"System information audit completed with score: {score}")
            
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                score=score,
                issues=self.security_issues,
                metadata=metadata,
                timestamp=self.format_timestamp()
            )
            
        except Exception as e:
            self.log_error(f"System information audit failed: {str(e)}")
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
    
    def _gather_os_info(self):
        """Gather operating system information."""
        self.log_debug("Gathering OS information")
        
        try:
            # Get basic OS information
            self.os_info = SystemUtils.get_os_info()
            
            # Handle Windows compatibility for user/group info
            if HAS_UNIX_MODULES:
                # Get user and group information (Unix systems only)
                try:
                    import pwd
                    import grp
                    self.os_info['user_count'] = len(pwd.getpwall())
                    self.os_info['group_count'] = len(grp.getgrall())
                except Exception as e:
                    self.log_debug(f"Could not get user/group info: {str(e)}")
                    self.os_info['user_count'] = 'unknown'
                    self.os_info['group_count'] = 'unknown'
            else:
                # Windows systems
                self.os_info['user_count'] = 'unknown'
                self.os_info['group_count'] = 'unknown'
            
            # Get additional details
            self.os_info.update({
                'hostname': socket.gethostname(),
                'fqdn': socket.getfqdn(),
                'uptime': SystemUtils.get_uptime(),
                'is_virtual_machine': SystemUtils.is_virtual_machine(),
                'kernel_version': SystemUtils.get_kernel_version()
            })
            
            # Get distribution-specific information
            self._get_distribution_info()
            
            self.log_debug(f"OS Information: {json.dumps(self.os_info, indent=2)}")
            
        except Exception as e:
            self.log_error(f"Failed to gather OS information: {str(e)}")
            self.security_issues.append(
                self.create_issue(
                    title="OS Information Gathering Failed",
                    description=f"Unable to collect operating system information: {str(e)}",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Check system permissions and ensure required system commands are available",
                    affected_files=[],
                    evidence=[f"Error: {str(e)}"]
                )
            )
    
    def _get_distribution_info(self):
        """Get distribution-specific information."""
        try:
            distro_id = self.os_info.get('distribution_id', 'unknown').lower()
            
            # Get package manager information
            package_managers = {
                'ubuntu': 'apt',
                'debian': 'apt',
                'centos': 'yum',
                'rhel': 'yum',
                'fedora': 'dnf'
            }
            
            self.os_info['package_manager'] = package_managers.get(distro_id, 'unknown')
            
            # Get installed packages count (sample)
            if self.os_info['package_manager'] == 'apt':
                result = CommandUtils.run_command(['dpkg', '-l'], timeout=10)
                if result['success']:
                    lines = result['stdout'].strip().split('\n')
                    self.os_info['installed_packages'] = len(lines) - 5  # Subtract header lines
                else:
                    self.os_info['installed_packages'] = 'unknown'
            elif self.os_info['package_manager'] in ['yum', 'dnf']:
                result = CommandUtils.run_command([self.os_info['package_manager'], 'list', 'installed'], timeout=10)
                if result['success']:
                    lines = result['stdout'].strip().split('\n')
                    self.os_info['installed_packages'] = len(lines) - 1  # Subtract header
                else:
                    self.os_info['installed_packages'] = 'unknown'
            
        except Exception as e:
            self.log_debug(f"Could not get distribution details: {str(e)}")
    
    def _gather_hardware_info(self):
        """Gather hardware details."""
        self.log_debug("Gathering hardware information")
        
        try:
            # CPU information
            cpu_info = {
                'physical_cores': psutil.cpu_count(logical=False),
                'logical_cores': psutil.cpu_count(logical=True),
                'max_frequency': psutil.cpu_freq().max if psutil.cpu_freq() else 0,
                'current_frequency': psutil.cpu_freq().current if psutil.cpu_freq() else 0,
                'cpu_usage': psutil.cpu_percent(interval=1)
            }
            
            # Memory information
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            memory_info = {
                'total': memory.total,
                'available': memory.available,
                'used': memory.used,
                'percentage': memory.percent,
                'swap_total': swap.total,
                'swap_used': swap.used,
                'swap_percentage': swap.percent
            }
            
            # Disk information
            disk_info = {}
            try:
                partitions = psutil.disk_partitions()
                for partition in partitions:
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        disk_info[partition.mountpoint] = {
                            'device': partition.device,
                            'fstype': partition.fstype,
                            'total': usage.total,
                            'used': usage.used,
                            'free': usage.free,
                            'percentage': (usage.used / usage.total) * 100 if usage.total > 0 else 0
                        }
                    except PermissionError:
                        # Skip partitions we can't access
                        continue
            except Exception as e:
                self.log_debug(f"Could not get disk information: {str(e)}")
            
            # Network interfaces
            network_interfaces = NetworkUtils.get_network_interfaces()
            
            # Combine all hardware info
            self.hardware_info = {
                'cpu': cpu_info,
                'memory': memory_info,
                'disks': disk_info,
                'network_interfaces': network_interfaces,
                'architecture': platform.architecture(),
                'machine_type': platform.machine()
            }
            
            self.log_debug(f"Hardware Information: {json.dumps(self.hardware_info, indent=2, default=str)}")
            
        except Exception as e:
            self.log_error(f"Failed to gather hardware information: {str(e)}")
            self.security_issues.append(
                self.create_issue(
                    title="Hardware Information Gathering Failed",
                    description=f"Unable to collect hardware information: {str(e)}",
                    severity=SeverityLevel.MEDIUM,
                    recommendation="Check system permissions and ensure psutil is properly installed",
                    affected_files=[],
                    evidence=[f"Error: {str(e)}"]
                )
            )
    
    def _detect_kernel_modules(self):
        """Detect loaded kernel modules."""
        self.log_debug("Detecting kernel modules")
        
        try:
            # Try different methods to get kernel modules
            modules_result = CommandUtils.run_command(['lsmod'], timeout=10)
            
            if modules_result['success']:
                lines = modules_result['stdout'].strip().split('\n')[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 3:
                        self.kernel_modules.append({
                            'name': parts[0],
                            'size': int(parts[1]),
                            'used_by': parts[2] if len(parts) > 2 else '0'
                        })
            else:
                # Try alternative method
                try:
                    with open('/proc/modules', 'r') as f:
                        for line in f:
                            parts = line.split()
                            if len(parts) >= 3:
                                self.kernel_modules.append({
                                    'name': parts[0],
                                    'size': int(parts[1]),
                                    'used_by': parts[2] if len(parts) > 2 else '0'
                                })
                except Exception:
                    pass
            
            self.log_debug(f"Detected {len(self.kernel_modules)} kernel modules")
            
        except Exception as e:
            self.log_error(f"Failed to detect kernel modules: {str(e)}")
            self.security_issues.append(
                self.create_issue(
                    title="Kernel Module Detection Failed",
                    description=f"Unable to detect loaded kernel modules: {str(e)}",
                    severity=SeverityLevel.LOW,
                    recommendation="Check system permissions and ensure lsmod command is available",
                    affected_files=[],
                    evidence=[f"Error: {str(e)}"]
                )
            )
    
    def _check_system_config(self):
        """Check system configuration files."""
        self.log_debug("Checking system configuration files")
        
        try:
            config_files = [
                '/etc/issue',
                '/etc/motd',
                '/etc/hosts',
                '/etc/resolv.conf',
                '/etc/environment',
                '/etc/profile',
                '/etc/bash.bashrc'
            ]
            
            for config_file in config_files:
                try:
                    if os.path.exists(config_file):
                        permissions = FileUtils.get_file_permissions(config_file)
                        self.system_config[config_file] = {
                            'exists': True,
                            'permissions': permissions,
                            'size': permissions.get('size', 0),
                            'modified': permissions.get('modified', 'unknown')
                        }
                        
                        # Check for security issues
                        self._check_config_security(config_file, permissions)
                    else:
                        self.system_config[config_file] = {'exists': False}
                        
                except Exception as e:
                    self.log_debug(f"Could not check {config_file}: {str(e)}")
                    self.system_config[config_file] = {'error': str(e)}
            
            self.log_debug(f"Checked {len(self.system_config)} configuration files")
            
        except Exception as e:
            self.log_error(f"Failed to check system configuration: {str(e)}")
    
    def _check_config_security(self, config_file: str, permissions: Dict[str, Any]):
        """Check security of configuration file."""
        try:
            # Check if file is world-writable
            if FileUtils.is_writable_by_others(config_file):
                self.security_issues.append(
                    self.create_issue(
                        title=f"World-writable configuration file: {config_file}",
                        description=f"Configuration file {config_file} is writable by group or others",
                        severity=SeverityLevel.HIGH,
                        recommendation=f"Change permissions to 644 or more restrictive: chmod 644 {config_file}",
                        affected_files=[config_file],
                        evidence=[f"Permissions: {permissions.get('permissions', 'unknown')}"]
                    )
                )
            
            # Check for sensitive files with weak permissions
            sensitive_files = ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers']
            if config_file in sensitive_files:
                numeric_perms = permissions.get('numeric', '0000')
                if config_file in ['/etc/shadow', '/etc/sudoers'] and numeric_perms != '600':
                    self.security_issues.append(
                        self.create_issue(
                            title=f"Weak permissions on sensitive file: {config_file}",
                            description=f"Sensitive file {config_file} has weak permissions ({numeric_perms})",
                            severity=SeverityLevel.CRITICAL,
                            recommendation=f"Set secure permissions: chmod 600 {config_file}",
                            affected_files=[config_file],
                            evidence=[f"Current permissions: {numeric_perms}"]
                        )
                    )
        
        except Exception as e:
            self.log_debug(f"Could not check security for {config_file}: {str(e)}")
    
    def _check_kernel_security(self):
        """Check kernel security settings."""
        self.log_debug("Checking kernel security settings")
        
        try:
            # Check kernel version for known vulnerabilities
            kernel_version = self.os_info.get('kernel_version', '')
            if kernel_version:
                self._check_kernel_version(kernel_version)
            
            # Check kernel parameters
            self._check_kernel_parameters()
            
            # Check for dangerous kernel modules
            self._check_dangerous_modules()
            
        except Exception as e:
            self.log_error(f"Failed to check kernel security: {str(e)}")
    
    def _check_kernel_version(self, kernel_version: str):
        """Check kernel version against known vulnerabilities."""
        try:
            # Extract version numbers
            version_match = re.match(r'(\d+\.\d+\.\d+)', kernel_version)
            if version_match:
                version = version_match.group(1)
                
                # Check against known vulnerable versions
                # This is a simplified check - in production, use a CVE database
                vulnerable_versions = [
                    '4.4.0', '4.15.0', '5.4.0'  # Example vulnerable versions
                ]
                
                if version in vulnerable_versions:
                    self.security_issues.append(
                        self.create_issue(
                            title="Outdated kernel version",
                            description=f"Kernel version {kernel_version} may have known security vulnerabilities",
                            severity=SeverityLevel.HIGH,
                            recommendation="Update to the latest stable kernel version",
                            affected_files=[],
                            evidence=[f"Kernel version: {kernel_version}"],
                            cve_id="CVE-2023-XXXXX"  # Example CVE
                        )
                    )
        
        except Exception as e:
            self.log_debug(f"Could not check kernel version: {str(e)}")
    
    def _check_kernel_parameters(self):
        """Check kernel security parameters."""
        try:
            # Check important security parameters
            security_params = {
                '/proc/sys/kernel/dmesg_restrict': '1',
                '/proc/sys/kernel/kptr_restrict': '2',
                '/proc/sys/kernel/yama/ptrace_scope': '1',
                '/proc/sys/net/ipv4/ip_forward': '0',
                '/proc/sys/net/ipv4/conf/all/send_redirects': '0',
                '/proc/sys/net/ipv4/conf/all/accept_redirects': '0',
                '/proc/sys/net/ipv4/conf/all/accept_source_route': '0',
                '/proc/sys/net/ipv6/conf/all/accept_redirects': '0',
                '/proc/sys/net/ipv6/conf/all/accept_source_route': '0'
            }
            
            for param_file, expected_value in security_params.items():
                try:
                    if os.path.exists(param_file):
                        with open(param_file, 'r') as f:
                            current_value = f.read().strip()
                        
                        if current_value != expected_value:
                            self.security_issues.append(
                                self.create_issue(
                                    title=f"Kernel parameter misconfiguration: {param_file}",
                                    description=f"Kernel parameter {param_file} has value {current_value}, expected {expected_value}",
                                    severity=SeverityLevel.MEDIUM,
                                    recommendation=f"Set parameter value: echo {expected_value} > {param_file}",
                                    affected_files=[param_file],
                                    evidence=[f"Current value: {current_value}"]
                                )
                            )
                except Exception as e:
                    self.log_debug(f"Could not check {param_file}: {str(e)}")
        
        except Exception as e:
            self.log_debug(f"Could not check kernel parameters: {str(e)}")
    
    def _check_dangerous_modules(self):
        """Check for dangerous kernel modules."""
        try:
            # List of potentially dangerous modules
            dangerous_modules = [
                'usb-storage',  # Can be used for data exfiltration
                'firewire-sbp2',  # FireWire storage
                'bluetooth',  # Bluetooth stack
                'rfcomm',  # Bluetooth RFCOMM
                'bnep',  # Bluetooth networking
                'nfs',  # NFS client
                'cifs',  # CIFS/SMB client
                'vfat',  # FAT filesystem
                'ntfs'  # NTFS filesystem
            ]
            
            loaded_modules = [module['name'] for module in self.kernel_modules]
            
            for module in dangerous_modules:
                if module in loaded_modules:
                    self.security_issues.append(
                        self.create_issue(
                            title=f"Potentially dangerous kernel module loaded: {module}",
                            description=f"Kernel module {module} is loaded and may pose security risks",
                            severity=SeverityLevel.MEDIUM,
                            recommendation=f"Unload module if not needed: modprobe -r {module}",
                            affected_files=[],
                            evidence=[f"Module: {module}"]
                        )
                    )
        
        except Exception as e:
            self.log_debug(f"Could not check dangerous modules: {str(e)}")
    
    def _check_system_updates(self):
        """Check system update status."""
        self.log_debug("Checking system update status")
        
        try:
            distro_id = self.os_info.get('distribution_id', 'unknown').lower()
            
            if distro_id in ['ubuntu', 'debian']:
                # Check for available updates
                result = CommandUtils.run_command(['apt', 'list', '--upgradable'], timeout=30)
                if result['success']:
                    lines = result['stdout'].strip().split('\n')
                    if len(lines) > 1:  # More than just header
                        update_count = len(lines) - 1
                        self.security_issues.append(
                            self.create_issue(
                                title="System updates available",
                                description=f"{update_count} package updates are available",
                                severity=SeverityLevel.MEDIUM if update_count < 10 else SeverityLevel.HIGH,
                                recommendation="Install available updates: apt update && apt upgrade",
                                affected_files=[],
                                evidence=[f"Updates available: {update_count}"]
                            )
                        )
            
            elif distro_id in ['centos', 'rhel', 'fedora']:
                # Check for available updates
                package_manager = self.os_info.get('package_manager', 'yum')
                result = CommandUtils.run_command([package_manager, 'check-update'], timeout=30)
                if result['success'] and result['stdout'].strip():
                    lines = result['stdout'].strip().split('\n')
                    update_count = len(lines)
                    self.security_issues.append(
                        self.create_issue(
                            title="System updates available",
                            description=f"{update_count} package updates are available",
                            severity=SeverityLevel.MEDIUM if update_count < 10 else SeverityLevel.HIGH,
                            recommendation="Install available updates",
                            affected_files=[],
                            evidence=[f"Updates available: {update_count}"]
                        )
                    )
        
        except Exception as e:
            self.log_debug(f"Could not check update status: {str(e)}")
    
    def _check_service_configuration(self):
        """Check service configuration."""
        self.log_debug("Checking service configuration")
        
        try:
            # Get list of running services
            processes = CommandUtils.get_process_list()
            
            # Check for services running as root
            root_services = [p for p in processes if p.get('username') == 'root']
            
            # Check for unnecessary services
            unnecessary_services = [
                'telnet', 'rsh', 'rlogin', 'ftp', 'tftp',
                'chargen', 'daytime', 'discard', 'echo', 'time'
            ]
            
            for service in unnecessary_services:
                matching_processes = [p for p in processes if service in p.get('name', '').lower()]
                if matching_processes:
                    self.security_issues.append(
                        self.create_issue(
                            title=f"Potentially unnecessary service running: {service}",
                            description=f"Service {service} is running and may not be needed",
                            severity=SeverityLevel.LOW,
                            recommendation=f"Consider stopping and disabling the service: systemctl disable {service}",
                            affected_files=[],
                            evidence=[f"Process: {matching_processes[0].get('name', service)}"]
                        )
                    )
        
        except Exception as e:
            self.log_debug(f"Could not check service configuration: {str(e)}")
    
    def _check_resource_usage(self):
        """Check system resource usage."""
        self.log_debug("Checking resource usage")
        
        try:
            # Check memory usage
            memory = self.hardware_info.get('memory', {})
            memory_usage = memory.get('percentage', 0)
            
            if memory_usage > 90:
                self.security_issues.append(
                    self.create_issue(
                        title="High memory usage detected",
                        description=f"System memory usage is {memory_usage:.1f}%",
                        severity=SeverityLevel.MEDIUM,
                        recommendation="Investigate memory usage and consider adding more RAM or optimizing applications",
                        affected_files=[],
                        evidence=[f"Memory usage: {memory_usage:.1f}%"]
                    )
                )
            
            # Check disk usage
            disks = self.hardware_info.get('disks', {})
            for mount_point, disk_info in disks.items():
                usage = disk_info.get('percentage', 0)
                if usage > 90:
                    self.security_issues.append(
                        self.create_issue(
                            title=f"High disk usage on {mount_point}",
                            description=f"Disk usage on {mount_point} is {usage:.1f}%",
                            severity=SeverityLevel.MEDIUM,
                            recommendation=f"Clean up disk space on {mount_point}",
                            affected_files=[mount_point],
                            evidence=[f"Disk usage: {usage:.1f}%"]
                        )
                    )
            
            # Check CPU usage
            cpu = self.hardware_info.get('cpu', {})
            cpu_usage = cpu.get('cpu_usage', 0)
            
            if cpu_usage > 90:
                self.security_issues.append(
                    self.create_issue(
                        title="High CPU usage detected",
                        description=f"System CPU usage is {cpu_usage:.1f}%",
                        severity=SeverityLevel.MEDIUM,
                        recommendation="Investigate CPU usage and optimize applications",
                        affected_files=[],
                        evidence=[f"CPU usage: {cpu_usage:.1f}%"]
                    )
                )
        
        except Exception as e:
            self.log_debug(f"Could not check resource usage: {str(e)}")


def create_module(config):
    """
    Factory function to create a SystemInfoModule instance.
    
    Args:
        config: Configuration object
        
    Returns:
        SystemInfoModule instance
    """
    return SystemInfoModule(config)